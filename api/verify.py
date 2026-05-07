"""
api/verify.py — Vercel Serverless Function
يستقبل بيانات البصمة ويتحقق منها عبر MongoDB
"""
from http.server import BaseHTTPRequestHandler
import json
import os
import hashlib
from datetime import datetime, timezone
from pymongo import MongoClient

# ─── إعدادات ─────────────────────────────────────────────────────
MONGO_URI   = os.environ.get("MONGO_URI", "mongodb+srv://aabohasn97_db_user:Wu0dwnqjDa8V7LG6@greg.lk9lpsg.mongodb.net/greeg?appName=GREG")
BOT_SECRET  = os.environ.get("BOT_SECRET", "GREEG_SECRET_2024")  # سر مشترك بين البوت والـ API

# ─── اتصال MongoDB ───────────────────────────────────────────────
_client = None
def get_db():
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    return _client["greeg"]

# ─── دوال مساعدة ─────────────────────────────────────────────────
def compute_combined_id(data: dict) -> str:
    """يولد ID مدمج من عدة طبقات للتعرف على الجهاز"""
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
    combined = "|".join(components)
    return hashlib.sha256(combined.encode()).hexdigest()

def extract_ip(environ) -> str:
    """يستخرج IP الحقيقي"""
    for header in ["HTTP_X_FORWARDED_FOR", "HTTP_X_REAL_IP", "REMOTE_ADDR"]:
        ip = environ.get(header, "")
        if ip:
            return ip.split(",")[0].strip()
    return "unknown"

# ─── معالج الطلبات ───────────────────────────────────────────────
class handler(BaseHTTPRequestHandler):

    def do_OPTIONS(self):
        """CORS preflight"""
        self.send_response(200)
        self._cors_headers()
        self.end_headers()

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            data   = json.loads(body)
        except Exception:
            self._respond(400, {"success": False, "message": "بيانات غير صالحة"})
            return

        token  = data.get("token", "").strip()
        if not token:
            self._respond(400, {"success": False, "message": "رابط التحقق غير صالح"})
            return

        db     = get_db()
        ip     = extract_ip(self.server.__dict__.get("environ", {}))
        device_id = compute_combined_id(data)

        # ── 1. تحقق من صحة التوكن ────────────────────────────────
        pending = db["pending_verifications"].find_one({"token": token})
        if not pending:
            self._respond(403, {"success": False, "message": "رابط التحقق منتهي الصلاحية أو غير صالح"})
            return

        discord_id = str(pending["discord_id"])
        guild_id   = str(pending["guild_id"])

        # ── 2. تحقق من الحظر (IP) ────────────────────────────────
        banned_ip = db["bans"].find_one({"type": "ip", "value": ip, "guild_id": guild_id})
        if banned_ip:
            self._log_attempt(db, discord_id, guild_id, ip, device_id, "banned_ip")
            self._respond(403, {"success": False, "banned": True,
                                "message": "شبكتك محظورة من هذا السيرفر"})
            return

        # ── 3. تحقق من الحظر (Device) ────────────────────────────
        banned_device = db["bans"].find_one({"type": "device", "value": device_id, "guild_id": guild_id})
        if banned_device:
            self._log_attempt(db, discord_id, guild_id, ip, device_id, "banned_device")
            self._respond(403, {"success": False, "banned": True,
                                "message": "جهازك محظور من هذا السيرفر"})
            return

        # ── 4. تحقق من الحظر (Canvas/WebGL) ─────────────────────
        canvas_id = data.get("canvasFp", "")
        banned_canvas = db["bans"].find_one({"type": "canvas", "value": canvas_id, "guild_id": guild_id})
        if banned_canvas:
            self._log_attempt(db, discord_id, guild_id, ip, device_id, "banned_canvas")
            self._respond(403, {"success": False, "banned": True,
                                "message": "جهازك محظور من هذا السيرفر"})
            return

        # ── 5. حفظ بصمة العضو وتمييزه كـ verified ────────────────
        db["members"].update_one(
            {"discord_id": discord_id, "guild_id": guild_id},
            {"$set": {
                "discord_id":   discord_id,
                "guild_id":     guild_id,
                "ip":           ip,
                "device_id":    device_id,
                "canvas_fp":    canvas_id,
                "webgl":        data.get("webglRenderer", ""),
                "storage_fp":   data.get("storageFp", ""),
                "cookie_fp":    data.get("cookieFp", ""),
                "user_agent":   data.get("userAgent", ""),
                "screen":       f"{data.get('screenW')}x{data.get('screenH')}",
                "timezone":     data.get("timezone", ""),
                "verified_at":  datetime.now(timezone.utc),
                "full_data":    data,
            }},
            upsert=True
        )

        # ── 6. حذف التوكن المستخدم ───────────────────────────────
        db["pending_verifications"].delete_one({"token": token})

        # ── 7. إشعار البوت بالقبول ───────────────────────────────
        db["verification_queue"].insert_one({
            "discord_id": discord_id,
            "guild_id":   guild_id,
            "action":     "approve",
            "timestamp":  datetime.now(timezone.utc),
        })

        self._respond(200, {"success": True, "message": "تم التحقق بنجاح"})

    def _respond(self, code: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self._cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _log_attempt(self, db, discord_id, guild_id, ip, device_id, reason):
        db["blocked_attempts"].insert_one({
            "discord_id": discord_id,
            "guild_id":   guild_id,
            "ip":         ip,
            "device_id":  device_id,
            "reason":     reason,
            "timestamp":  datetime.now(timezone.utc),
        })

    def log_message(self, *args): pass  # تعطيل logs الافتراضية

