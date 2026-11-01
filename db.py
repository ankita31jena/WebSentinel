from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

client = MongoClient(os.getenv("MONGO_URI"))
db     = client[os.getenv("MONGO_DB")]

scans_col  = db["scans"]
alerts_col = db["alerts"]

def save_scan(scan_data):
    return scans_col.insert_one(scan_data)

def save_alerts(alerts):
    if alerts:
        return alerts_col.insert_many(alerts)

def get_all_scans():
    return list(scans_col.find({}, {"_id": 0}))

def get_alerts_by_scan(scan_id):
    return list(alerts_col.find({"scan_id": scan_id}, {"_id": 0}))

def get_alerts_by_risk(risk):
    return list(alerts_col.find({"risk": risk}, {"_id": 0}))

def count_by_risk():
    pipeline = [{"$group": {"_id": "$risk", "count": {"$sum": 1}}}]
    return list(alerts_col.aggregate(pipeline))

def get_top_alerts(limit=10):
    pipeline = [
        {"$group": {"_id": "$name", "count": {"$sum": 1}, "risk": {"$first": "$risk"}}},
        {"$sort": {"count": -1}},
        {"$limit": limit}
    ]
    return list(alerts_col.aggregate(pipeline))

def get_alert_by_index(skip=0):
    return alerts_col.find({}, {"_id": 0}).skip(skip).limit(1)[0]
