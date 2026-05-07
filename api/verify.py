import json, os, hashlib
from datetime import datetime, timezone
from pymongo import MongoClient
from flask import Flask, request, jsonify

# 1. تعريف التطبيق (هذا هو السطر الذي كان ينقصك ليتعرف Vercel على الكود)
app = Flask(__name__)

# إعدادات قاعدة البيانات
MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://aabohasn97_db_user:Wu0dwnqjDa8V7LG6@greg.lk9lpsg.mongodb.net/greeg?appName=GREG")

_client = None
def get_db():
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    return _client["greeg"]

def compute_combined_id(data):
    parts = [data.get(k,"") for k in ["fingerprint","canvasFp","webglRenderer","audioFp","storageFp","cookieFp","platform"]]
    parts += [str(data.get("screenW","")), str(data.get("screenH",""))]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()

# 2. تحديد المسار (Route)
@app.route('/api/verify', methods=['POST', 'OPTIONS'])
def handler():
    # إعدادات الـ CORS والهيدرز
    h = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Content-Type": "application/json; charset=utf-8"
    }
    
    if request.method == "OPTIONS":
        return ("", 200, h)
        
    if request.method != "POST":
        return (json.dumps({"success": False, "message": "Method not allowed"}), 405, h)
        
    try:
        # الحصول على البيانات من الطلب
        data = request.get_json() or {}
    except:
        return (json.dumps({"success": False, "message": "بيانات غير صالحة"}, ensure_ascii=False), 400, h)
        
    token = data.get("token", "").strip()
    if not token:
        return (json.dumps({"success": False, "message": "رابط غير صالح"}, ensure_ascii=False), 400, h)
        
    try:
        db = get_db()
        # جلب الـ IP الخاص بالمستخدم
        ip = request.headers.get("x-forwarded-for", "unknown").split(",")[0].strip()
        device_id = compute_combined_id(data)
        guild_id = "1003257192104874004"
        
        # البحث عن التوكن في الانتظار
        pending = db["pending_verifications"].find_one({"token": token})
        if not pending:
            return (json.dumps({"success": False, "message": "رابط منتهي الصلاحية"}, ensure_ascii=False), 403, h)
            
        discord_id = str(pending["discord_id"])
        
        # فحص الحظر (Bans)
        for t, v in [("ip", ip), ("device", device_id), ("canvas", data.get("canvasFp", ""))]:
            if db["bans"].find_one({"type": t, "value": v, "guild_id": guild_id}):
                db["blocked_attempts"].insert_one({
                    "discord_id": discord_id,
                    "guild_id": guild_id,
                    "ip": ip,
                    "device_id": device_id,
                    "reason": f"banned_{t}",
                    "timestamp": datetime.now(timezone.utc)
                })
                return (json.dumps({"success": False, "banned": True, "message": "جهازك أو شبكتك محظورة"}, ensure_ascii=False), 403, h)
        
        # تحديث بيانات العضو
        db["members"].update_one(
            {"discord_id": discord_id, "guild_id": guild_id},
            {"$set": {
                "discord_id": discord_id,
                "guild_id": guild_id,
                "ip": ip,
                "device_id": device_id,
                "canvas_fp": data.get("canvasFp", ""),
                "webgl": data.get("webglRenderer", ""),
                "user_agent": data.get("userAgent", ""),
                "screen": f"{data.get('screenW')}x{data.get('screenH')}",
                "timezone": data.get("timezone", ""),
                "verified_at": datetime.now(timezone.utc)
            }},
            upsert=True
        )
        
        # حذف التوكن وإضافة العضو لطابور القبول
        db["pending_verifications"].delete_one({"token": token})
        db["verification_queue"].insert_one({
            "discord_id": discord_id,
            "guild_id": guild_id,
            "action": "approve",
            "timestamp": datetime.now(timezone.utc)
        })
        
        return (json.dumps({"success": True, "message": "تم التحقق بنجاح"}, ensure_ascii=False), 200, h)
        
    except Exception as e:
        return (json.dumps({"success": False, "message": str(e)}, ensure_ascii=False), 500, h)

# هذا السطر مهم لتشغيل Flask محلياً إذا أردت التجربة
if __name__ == "__main__":
    app.run(debug=True)
