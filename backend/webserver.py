from fastapi import FastAPI, Request
import time
from datetime import datetime
from backend.elastic_handler import ElasticHandler
from backend.elastic_handler import HONEYPOT_INDEX  # Import the constant

app = FastAPI()
es_handler = ElasticHandler()

@app.get("/{path:path}")
@app.post("/{path:path}")
async def capture_requests(request: Request, path: str):
    """Capture all HTTP requests and log them."""
    client_ip = request.client.host
    headers = dict(request.headers)
    method = request.method
    body = await request.body()

    # Get the current timestamp and convert it to ISO 8601 format
    timestamp = datetime.utcfromtimestamp(time.time()).isoformat()

    # Extract individual headers
    log_data = {
        "timestamp": timestamp,  # Store the ISO 8601 formatted timestamp
        "ip": client_ip,
        "method": method,
        "path": path,
        "host": headers.get("host", ""),
        "user_agent": headers.get("user-agent", ""),
        "accept": headers.get("accept", ""),
        "accept_language": headers.get("accept-language", ""),
        "connection": headers.get("connection", ""),
        "content_type": headers.get("content-type", ""),
        # Add other headers as needed
        "body": body.decode("utf-8") if body else "",
    }

    # Store logs in Elasticsearch, explicitly passing the index
    es_handler.store_log(HONEYPOT_INDEX, log_data)

    return {"message": "Logged", "client_ip": client_ip}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)