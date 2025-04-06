import os
import subprocess
import sys
import time
from celery import Celery
from backend.log_handler import log_event
import signal
import psutil

# Get Redis settings from environment variables (using defaults if not found)
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_DB = os.getenv("REDIS_DB", "0")
REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"

# Set up Celery app with Redis broker and backend for task tracking
celery_app = Celery(
    'processing',
    broker=REDIS_URL,  # Redis broker URL from env
    backend=REDIS_URL  # Redis backend to track task status
)

# Auto-discover tasks in the backend module
celery_app.autodiscover_tasks(['backend'])


# Celery task definition
@celery_app.task
def run_parser():
    try:
        # Log the task start
        print(f"Started parsing process")

        # Run the parser as a subprocess (no file_hash needed)
        process = subprocess.Popen([sys.executable, '-m', 'backend.parser'])
        process.communicate()  # Wait for process completion

        # Log task success
        print(f"Finished parsing process")

    except Exception as e:
        # Log the error and retry the task
        print(f"Error processing task: {str(e)}")
        raise run_parser.retry(exc=e, countdown=60, max_retries=3)


# Celery task definition to run the elastic_indexer
@celery_app.task
def run_elastic_indexer():
    try:
        # Log the task start
        print(f"Started Elasticsearch indexing process")

        # Run the elastic_indexer as a subprocess
        process = subprocess.Popen([sys.executable, '-m', 'backend.elastic_indexer'])
        process.communicate()  # Wait for process completion

        # Log task success
        print(f"Finished Elasticsearch indexing process")

    except Exception as e:
        # Log the error and retry the task
        print(f"Error processing task: {str(e)}")
        raise run_elastic_indexer.retry(exc=e, countdown=60, max_retries=3)


def run_celery_worker():
    """Run Celery worker as a background process and terminate it when the main script exits."""
    try:
        print("Starting Celery worker in the background...")

        # Start the Celery worker and suppress output (send to a log file or /dev/null)
        celery_worker = subprocess.Popen(
            ['celery', '-A', 'backend.celery_handler', 'worker', '--loglevel=info'],
            stdout=open(os.devnull, 'w'),  # Suppress stdout
            stderr=open(os.devnull, 'w'),  # Suppress stderr
        )

        # Give Celery a moment to initialize
        time.sleep(3)

        print(f"Celery worker started with PID {celery_worker.pid}.")

        return celery_worker  # Return the process object

    except Exception as e:
        print(f"Error starting Celery worker: {str(e)}")
        return None

if __name__ == "__main__":
    # Run Celery worker and trigger the task
    run_celery_worker()