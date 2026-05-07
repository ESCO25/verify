"""
api/verify.py — Vercel Serverless Function (Fixed)
"""
import json
import os
import hashlib
from datetime import datetime, timezone
from pymongo import MongoClient

MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://aabohasn97_db_user:Wu0dwnqjDa8V7LG6@greg.lk9lpsg.mongodb.net/greeg?appName=GREG")

_client = None
def get_db():
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    return _client["greeg"]

def compute_combined_id(data):
    components = [
        data.get("fingerprint", ""),
        data.get("canvasFp", ""),
        data.get("webglRenderer", ""),
        data.get("audioFp", ""),
        data.get("storageFp", ""),
        data.get("cookieFp", ""),
        str(data.get("screenW", "")),
        str(data.get("screenH", "")),
        data.get("platform", ""),
    ]
    return hashlib.sha256("|".join(components).encode()).hexdigest()

def handler(request):
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Content-Type": "application/json; charset=utf-8",
    }

    if request.method == "OPTIONS":
        return ("", 200, headers)

    if request.method != "POST":
        return (json.dumps({"success": False, "message": "Method not allowed"}), 405, headers)

    try:
        data = request.get_json()
    except Exception:
        return (json.dumps({"success": False, "message": "بيانات غير صالحة"}, ensure_ascii=False), 400, headers)

    token = (data or {}).get("token", "").strip()
    if not token:
        return (json.dumps({"success": False, "message": "رابط التحقق غير صالح"}, ensure_ascii=False), 400, headers)

    try:
        db = get_db()
        ip = request.headers.get("x-forwarded-for", "unknown").split(",")[0].strip()
        device_id = compute_combined_id(data)
        guild_id = "1003257192104874004"

        pending = db["pending_verifications"].find_one({"token": token})
        if not pending:
            return (json.dumps({"success": False, "message": "رابط التحقق منتهي الصلاحية"}, ensure_ascii=False), 403, headers)

        discord_id = str(pending["discord_id"])

        for ban_type, ban_value in [
            ("ip", ip),
            ("device", device_id),
            ("canvas", data.get("canvasFp", "")),
        ]:
            if db["bans"].find_one({"type": ban_type, "value": ban_value, "guild_id": guild_id}):
                db["blocked_attempts"].insert_one({
                    "discord_id": discord_id,
                    "guild_id": guild_id,
                    "ip": ip,
                    "device_id": device_id,
                    "reason": f"banned_{ban_type}",
                    "timestamp": datetime.now(timezone.utc),
                })
                return (json.dumps({"success": False, "banned": True, "message": "جهازك أو شبكتك محظورة"}, ensure_ascii=False), 403, headers)

        db["members"].update_one(
            {"discord_id": discord_id, "guild_id": guild_id},
            {"$set": {
                "discord_id": discord_id,
                "guild_id": guild_id,
                "ip": ip,
                "device_id": device_id,
                "canvas_fp": data.get("canvasFp", ""),
                "webgl": data.get("webglRenderer", ""),
                "storage_fp": data.get("storageFp", ""),
                "cookie_fp": data.get("cookieFp", ""),
                "user_agent": data.get("userAgent", ""),
                "screen": f"{data.get('screenW')}x{data.get('screenH')}",
                "timezone": data.get("timezone", ""),
                "verified_at": datetime.now(timezone.utc),
            }},
            upsert=True
        )

        db["pending_verifications"].delete_one({"token": token})

        db["verification_queue"].insert_one({
            "discord_id": discord_id,
            "guild_id": guild_id,
            "action": "approve",
            "timestamp": datetime.now(timezone.utc),
        })

        return (json.dumps({"success": True, "message": "تم التحقق بنجاح"}, ensure_ascii=False), 200, headers)

    except Exception as e:
        return (json.dumps({"success": False, "message": f"خطأ: {str(e)}"}, ensure_ascii=False), 500, headers)
