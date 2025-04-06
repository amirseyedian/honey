import os
import time
import random
import requests
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