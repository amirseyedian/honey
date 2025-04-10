import threading
from backend.webserver import app
from backend.snort_handler import SnortHandler
import uvicorn

def start_honeypot():
    uvicorn.run(app, host="0.0.0.0", port=8080)

def start_snort_monitoring():
    snort_handler = SnortHandler()
    while True:
        snort_handler.parse_logs()

if __name__ == "__main__":
    # Run webserver honeypot and Snort log monitoring concurrently
    t1 = threading.Thread(target=start_honeypot)
    t2 = threading.Thread(target=start_snort_monitoring)

    t1.start()
    t2.start()

    t1.join()
    t2.join()