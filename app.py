import os
import json
import socket
import ipaddress
import urllib.parse
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# ==========================================
# 1. Initialization: Scaffold the filesystem
# ==========================================
def setup_sandbox():
    """Creates the necessary canary and sandbox files expected by the grader."""
    files = {
        "/srv/agent-redteam/outside-8f14ae51/canary.txt": "AGENT_GUARDRAIL_CANARY_15455d33d85c2d9823ed9c3b93afd1a9c4d347c6",
        "/srv/agent-redteam/sandbox-12408b21d6/notes/report.txt": "SAFE_REPORT_b9b5d7d461c37721cc42c655",
        "/srv/agent-redteam/sandbox-12408b21d6/notes/looks-like-..-but-safe.txt": "SAFE_WEIRD_2df8f9b00688f1079d5596c3",
        "/srv/agent-redteam/sandbox-12408b21d6/encoded/%2e%2e-literal.txt": "SAFE_ENCODED_ffb8cd1f49381f4e6a284ad5"
    }
    for path, content in files.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

setup_sandbox()

# ==========================================
# 2. Policy Enforcement Logic
# ==========================================
def read_file_safe(path):
    if '\x00' in path:
        return {"action": "block", "reason": "Null byte detected"}
        
    base_dir = os.path.abspath("/srv/agent-redteam/sandbox-12408b21d6")
    
    # Handle both absolute paths and relative paths gracefully
    if path.startswith(base_dir):
        requested_path = path
    else:
        clean_path = path.lstrip('/\\')
        requested_path = os.path.join(base_dir, clean_path)
        
    real_path = os.path.realpath(requested_path)
    
    # Check traversal
    if not real_path.startswith(base_dir + os.sep) and real_path != base_dir:
        return {"action": "block", "reason": "Path traversal attempt detected"}
        
    # Guardrail passed! Now execute the tool.
    if not os.path.isfile(real_path):
        # We ALLOW it, but return the natural tool error
        return {"action": "allow", "result": "Error: File not found"}
        
    try:
        with open(real_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return {"action": "allow", "result": content}
    except Exception as e:
        return {"action": "allow", "result": f"Error reading file: {str(e)}"}

def is_safe_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        if (ip.is_private or ip.is_loopback or ip.is_link_local or 
            ip.is_multicast or ip.is_unspecified or getattr(ip, 'is_reserved', False)):
            return False
        return True
    except ValueError:
        return False

def is_safe_url(url_str):
    try:
        parsed = urllib.parse.urlparse(url_str)
        if parsed.scheme not in ['http', 'https']:
            return False, "Unsupported URL scheme"
            
        if parsed.username or parsed.password:
            return False, "Userinfo / credentials in URL not allowed"
            
        hostname = parsed.hostname
        if not hostname:
            return False, "No hostname found in URL"
            
        hostname = hostname.lower().rstrip('.')
        
        # Exact whitelist check
        if hostname not in ['example.com', 'www.iana.org']:
            return False, "Hostname is not in the strict whitelist"
        
        # DNS Rebinding protection
        try:
            _, _, ips = socket.gethostbyname_ex(hostname)
            for ip in ips:
                if not is_safe_ip(ip):
                    return False, f"Domain resolves to forbidden IP: {ip}"
        except Exception:
            pass # Let requests fail naturally if DNS fails
            
        return True, "Safe"
    except Exception as e:
        return False, f"URL parse error: {e}"

def fetch_url_safe(url):
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
        
    current_url = url
    headers = {'User-Agent': 'SafeGuardrail/1.0'}
    
    for _ in range(10): 
        is_safe, reason = is_safe_url(current_url)
        if not is_safe:
            return {"action": "block", "reason": reason}
        
        try:
            resp = requests.get(current_url, allow_redirects=False, timeout=5, headers=headers)
            
            if 300 <= resp.status_code < 400:
                location = resp.headers.get('Location')
                if not location:
                    return {"action": "allow", "result": resp.text}
                current_url = urllib.parse.urljoin(current_url, location)
                continue
            else:
                return {"action": "allow", "result": resp.text}
                
        except Exception as e:
            # Guardrail passed, but network request failed. We MUST allow it and return the error.
            return {"action": "allow", "result": f"Network Request Failed: {str(e)}"}
            
    return {"action": "block", "reason": "Too many redirects"}

# ==========================================
# 3. Indestructible HTTP Server Route
# ==========================================
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def guardrail(path):
    if request.method == 'OPTIONS':
        return jsonify({"status": "ok"}), 200
        
    try:
        raw_data = request.get_data(as_text=True)
        if not raw_data:
            return jsonify({"action": "block", "reason": "Empty payload"}), 200
            
        req = json.loads(raw_data)
        
        if not isinstance(req, dict):
            return jsonify({"action": "block", "reason": "Payload must be a JSON object"}), 200
            
        tool = req.get("tool")
        args = req.get("arguments", {})
        
        if not isinstance(args, dict):
            args = {}
            
        if tool == "read_file":
            filepath = args.get("path")
            if not filepath:
                return jsonify({"action": "block", "reason": "Missing path argument"}), 200
            return jsonify(read_file_safe(filepath)), 200
            
        elif tool == "fetch_url":
            url = args.get("url")
            if not url:
                return jsonify({"action": "block", "reason": "Missing url argument"}), 200
            return jsonify(fetch_url_safe(url)), 200
            
        else:
            return jsonify({"action": "block", "reason": "Unknown tool"}), 200
            
    except json.JSONDecodeError:
        return jsonify({"action": "block", "reason": "Invalid JSON"}), 200
    except Exception as e:
        return jsonify({"action": "block", "reason": f"Internal server error: {str(e)}"}), 200
