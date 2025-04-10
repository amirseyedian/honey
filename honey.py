import threading
import time
import uvicorn

from backend.webserver import app
from backend.snort_handler import SnortHandler
from backend.elastic_handler import ElasticHandler, HONEYPOT_INDEX
from backend.enrich.iploc import enrich_ip

# Track the most recent honeypot doc timestamp to avoid redundant enrichments
latest_processed_timestamp = None
es_handler = ElasticHandler()

def start_honeypot():
    uvicorn.run(app, host="0.0.0.0", port=8080)

def start_snort_monitoring():
    snort_handler = SnortHandler()
    snort_handler.parse_logs()  # Blocking call

if __name__ == "__main__":
    # Thread: Webserver honeypot
    t1 = threading.Thread(target=start_honeypot)

    # Thread: Snort monitoring
    t2 = threading.Thread(target=start_snort_monitoring)

    t1.start()
    t2.start()
    t3.start()

    t1.join()
    t2.join()
    t3.join()