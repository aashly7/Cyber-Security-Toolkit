from flask import Flask, request, jsonify, render_template
import hashlib
import random
import string
import re
import requests
import socket

app = Flask(__name__)

# --- UTILITY FUNCTIONS ---

def scan_ports(target, start_port, end_port):
    open_ports = []
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return None, "Hostname could not be resolved."
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return open_ports, None

def password_strength(password):
    score = sum([
        len(password) >= 8,
        bool(re.search(r'[a-z]', password)),
        bool(re.search(r'[A-Z]', password)),
        bool(re.search(r'\\d', password)),
        bool(re.search(r'[!@#$%^&*(),.?\":{}|<>]', password))
    ])
    levels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
    return levels[score - 1] if score > 0 else levels[0]

def hash_text(text):
    return {
        "md5": hashlib.md5(text.encode()).hexdigest(),
        "sha1": hashlib.sha1(text.encode()).hexdigest(),
        "sha256": hashlib.sha256(text.encode()).hexdigest()
    }

def scan_vulnerabilities(url):
    try:
        if not url.startswith("http"):
            url = "http://" + url
        res = requests.get(url, timeout=5)
        headers = res.headers
        vulns = []
        if 'X-Powered-By' in headers:
            vulns.append("X-Powered-By header detected.")
        if 'X-Frame-Options' not in headers:
            vulns.append("Missing X-Frame-Options header.")
        if 'Content-Security-Policy' not in headers:
            vulns.append("Missing Content-Security-Policy (CSP) header.")
        if 'Strict-Transport-Security' not in headers:
            vulns.append("Missing Strict-Transport-Security header.")
        return {
            "server": headers.get("Server", "Unknown"),
            "vulnerabilities": vulns
        }, None
    except Exception as e:
        return None, str(e)

def generate_password(length):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# --- ROUTES ---

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/portscan", methods=["POST"])
def api_portscan():
    data = request.get_json()
    target = data.get("target", "")
    try:
        start_port = int(data.get("start_port", 1))
        end_port = int(data.get("end_port", 1024))
    except:
        return jsonify({"error": "Invalid port numbers."}), 400
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        return jsonify({"error": "Invalid port range."}), 400
    ports, error = scan_ports(target, start_port, end_port)
    if error:
        return jsonify({"error": error}), 400
    return jsonify({"open_ports": ports})

@app.route("/api/password_strength", methods=["POST"])
def api_password_strength():
    data = request.get_json()
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "Password required"}), 400
    return jsonify({"strength": password_strength(password)})

@app.route("/api/hash_generator", methods=["POST"])
def api_hash_generator():
    data = request.get_json()
    text = data.get("text", "")
    if not text:
        return jsonify({"error": "Text required"}), 400
    return jsonify(hash_text(text))

@app.route("/api/vuln_scan", methods=["POST"])
def api_vuln_scan():
    data = request.get_json()
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "URL required"}), 400
    result, error = scan_vulnerabilities(url)
    if error:
        return jsonify({"error": error}), 400
    return jsonify(result)

@app.route("/api/generate_password", methods=["POST"])
def api_generate_password():
    data = request.get_json()
    try:
        length = int(data.get("length", 12))
        if length < 8:
            return jsonify({"error": "Password must be at least 8 characters."}), 400
    except:
        return jsonify({"error": "Invalid length."}), 400
    return jsonify({"password": generate_password(length)})

if __name__ == "__main__":
    app.run(debug=True)
