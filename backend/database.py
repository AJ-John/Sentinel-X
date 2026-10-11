import os

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DB = os.getenv("MONGODB_DB", "sentinelx")

if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI is not configured in backend/.env")

client = MongoClient(MONGODB_URI)

database = client[MONGODB_DB]


def check_database_connection():
    try:
        client.admin.command("ping")
        return True
    except Exception:
        return False