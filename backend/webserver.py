import os
import time
import random
import requests
import re
from datetime import datetime
from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from config import WEBPAGE_FOLDER
from backend.elastic_handler import ElasticHandler
from backend.elastic_handler import HONEYPOT_INDEX

# Check if the folder exists
if not os.path.isdir(WEBPAGE_FOLDER):
    print(f"Warning: Webpage directory '{WEBPAGE_FOLDER}' does not exist or is not readable.")

FAKE_VULNERABLE_RESPONSES = {
    #"/phpmyadmin": "<h1>phpMyAdmin 4.9.0</h1><form>Username: <input><br>Password: <input type='password'></form>",
    "/wp-admin": "<h1>WordPress Admin</h1><form>Username: <input><br>Password: <input type='password'></form>",
    #"/admin/login": "<h1>Admin Panel</h1><form>Username: <input><br>Password: <input type='password'></form>",
    #"/robots.txt": "User-agent: *\nDisallow: /admin/\nDisallow: /wp-admin/\nDisallow: /.git/",
}

# Fake HTTP Headers (to appear outdated)
FAKE_SERVER_HEADERS = [
    #"Apache/2.4.49 (Ubuntu)",
    "nginx/1.14.2",
    #"Microsoft-IIS/7.5",
]

app = FastAPI()
es_handler = ElasticHandler()

# Serve static files from the user-defined folder
app.mount("/", StaticFiles(directory=WEBPAGE_FOLDER, html=True), name="static")

def identify_attack(path, body, headers):
    path = path.lower()
    body = body.lower() if body else ""
    user_agent = headers.get("user-agent", "").lower()

    # === SQL Injection ===
    sql_patterns = [
        r"(?i)\bunion\b\s+select\b",
        r"(?i)or\s+1\s*=\s*1",
        r"(?i)select\s+\*\s+from",
        r"(?i)insert\s+into",
        r"(?i)drop\s+table",
        r"(?i)--",
        r"(?i);--",
        r"'[\s]*or[\s]*'1'='1"
    ]
    for pattern in sql_patterns:
        if re.search(pattern, path) or re.search(pattern, body):
            return "SQL Injection"

    # === Cross-Site Scripting (XSS) ===
    xss_patterns = [
        r"<script.*?>.*?</script>",
        r"onerror\s*=",
        r"javascript:",
        r"<img\s+[^>]*src\s*="
    ]
    for pattern in xss_patterns:
        if re.search(pattern, path) or re.search(pattern, body):
            return "XSS"

    # === Command Injection ===
    cmd_patterns = [
        r";\s*",
        r"&&",
        r"\|\|",
        r"`.*?`",
        r"\$\(.*?\)",
        r"(?i)\bcurl\b",
        r"(?i)\bwget\b",
        r"(?i)\bping\s+-[a-z]*\b"
    ]
    for pattern in cmd_patterns:
        if re.search(pattern, body):
            return "Command Injection"

    # === Directory Traversal ===
    if re.search(r"(\.\./)+", path) or "%2e%2e" in path:
        return "Directory Traversal"

    # === File Inclusion (LFI/RFI) ===
    if re.search(r"(etc/passwd|boot.ini|input_file=|include\(|require\()", path):
        return "File Inclusion"

    # === Shell Upload Attempt ===
    if re.search(r"\.php[3457]?|\.asp|\.jsp|\.sh|\.exe|\.bat", path) and "upload" in path:
        return "Shell Upload Attempt"

    # === Authentication Bypass ===
    if re.search(r"(?i)(admin|login).*(=|%3D).*(true|1|'1'='1)", path + body):
        return "Authentication Bypass"

    # === Admin Panel Scan ===
    admin_paths = ["wp-login", "wp-admin", "admin", "phpmyadmin", "login.php"]
    if any(admin_path in path for admin_path in admin_paths):
        return "Admin Panel Scan"

    # === Bot/Scanner Detection ===
    bot_keywords = ["sqlmap", "nikto", "acunetix", "wpscan", "nmap", "curl", "httpie", "dirbuster"]
    if any(bot in user_agent for bot in bot_keywords):
        return "Scanner/Bot"

    # === Normal Browser Access Detection ===
    browser_signatures = ["mozilla", "chrome", "safari", "firefox", "edg", "opera"]
    if any(browser in user_agent for browser in browser_signatures):
        return "Normal Access"

    # === Default ===
    return "Unknown"

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all HTTP requests before processing."""
    client_ip = request.client.host
    headers = dict(request.headers)
    method = request.method
    path = request.url.path
    body = await request.body()

    # Get the current timestamp in ISO 8601 format
    timestamp = datetime.utcfromtimestamp(time.time()).isoformat()

    # Detect attack type
    attack_type = identify_attack(path, body.decode("utf-8"), headers)

    # Log request details
    log_data = {
        "timestamp": timestamp,
        "ip": client_ip,
        "method": method,
        "path": path,
        "host": headers.get("host", ""),
        "user_agent": headers.get("user-agent", ""),
        "accept": headers.get("accept", ""),
        "accept_language": headers.get("accept-language", ""),
        "connection": headers.get("connection", ""),
        "content_type": headers.get("content-type", ""),
        "body": body.decode("utf-8") if body else "",
        "attack_type": attack_type
    }

    # Store logs in Elasticsearch
    es_handler.store_log(HONEYPOT_INDEX, log_data)

    # Check for fake vulnerable endpoints
    if path in FAKE_VULNERABLE_RESPONSES:
        return Response(
            content=FAKE_VULNERABLE_RESPONSES[path],
            status_code=200,
            headers={"Server": random.choice(FAKE_SERVER_HEADERS)},
            media_type="text/html"
        )

    # Default to the original behavior
    response = await call_next(request)

    # If 404, return a fake vulnerable page instead
    if response.status_code == 404:
        fake_vuln_response = random.choice(list(FAKE_VULNERABLE_RESPONSES.values()))
        return Response(
            content=fake_vuln_response,
            status_code=200,
            headers={"Server": random.choice(FAKE_SERVER_HEADERS)},
            media_type="text/html"
        )

    return response

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
