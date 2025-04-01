import os
import time
import json
from elasticsearch import Elasticsearch

# Load environment variables
ELASTICSEARCH_HOST = os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")
ELASTICSEARCH_USER = os.getenv("ELASTICSEARCH_USER", "elastic")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "changeme")
SNORT_LOG_PATH = os.getenv("SNORT_LOG_PATH", "/var/log/snort/alert.fast")

# Connect to Elasticsearch
es = Elasticsearch(
    [ELASTICSEARCH_HOST],
    basic_auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD),
    verify_certs=False
)

# Function to parse Snort alert logs
def parse_snort_alert(line):

    try:
        parts = line.split("] [**] ")
        if len(parts) < 2:
            return None
        
        alert_info = parts[1].split(" [**]")[0]
        meta_data = parts[-1].strip()

        # Extract timestamp, source IP, and destination IP
        meta_parts = meta_data.split(" ")
        timestamp = meta_parts[0]
        src_ip, src_port = meta_parts[1].split(":")
        dst_ip, dst_port = meta_parts[3].split(":")

        return {
            "timestamp": timestamp,
            "alert": alert_info,
            "source_ip": src_ip,
            "source_port": src_port,
            "destination_ip": dst_ip,
            "destination_port": dst_port
        }
    except Exception as e:
        print(f"Error parsing Snort log: {e}")
        return None

# Function to watch Snort logs and send alerts to Elasticsearch
def watch_snort_logs():
    print(f"Watching Snort log file: {SNORT_LOG_PATH}")
    
    with open(SNORT_LOG_PATH, "r") as f:
        f.seek(0, os.SEEK_END)  # Move to the end of the file
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)  # Wait for new logs
                continue

            alert_data = parse_snort_alert(line)
            if alert_data:
                es.index(index="snort-logs", body=alert_data)
                print(f"Logged to Elasticsearch: {alert_data}")

if __name__ == "__main__":
    watch_snort_logs()