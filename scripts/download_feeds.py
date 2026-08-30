"""
Placeholder feed-download script.

For the hackathon demo, threat feeds live as static CSVs in /data
(populated already). This script is where the team wires up real feed
downloads (e.g. OpenPhish, URLhaus, PhishTank exports, or a STIX/TAXII
client) once network access and API keys are available -- keeping this
as a separate script means the live DNS path never depends on it.

Run with: python scripts/download_feeds.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.database.database import SessionLocal, init_db
from backend.threat_intelligence.feed_loader import sync_feeds_to_db


def main():
    init_db()
    db = SessionLocal()
    try:
        count = sync_feeds_to_db(db)
        print(f"Synced {count} indicators from local CSV feeds into the database.")
        print("TODO: replace with real STIX/TAXII / OpenPhish / URLhaus downloads.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
