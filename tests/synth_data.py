from backend.elastic_handler import  ElasticHandler
    
# Example honeypot log entry
store_log(HONEYPOT_INDEX, {
    "source_ip": "192.168.1.10",
    "request": "GET /admin",
    "headers": {
        "host": "localhost:8080",
        "user-agent": "curl/8.12.1",
        "accept": "*/*"
    }
})

# Example Snort log entry
store_log(SNORT_INDEX, {
    "timestamp": "2025-04-01T12:00:00",
    "alert": "ET SCAN Nmap User-Agent Detected",
    "source_ip": "10.0.0.5",
    "destination_ip": "192.168.1.20",
    "source_port": 56789,
    "destination_port": 443
})