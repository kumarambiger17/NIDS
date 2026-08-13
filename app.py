import os
import random
import sqlite3
import stat
import threading
import webbrowser
import cv2
import base64
import numpy as np
from datetime import datetime, timedelta

from flask import Flask, render_template, jsonify, request, redirect, url_for, session
from flask_mail import Mail, Message
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

from src.feature_extractor import extract_features
face_cascade = cv2.CascadeClassifier(
    cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
)

try:
    from twilio.rest import Client
    
except ImportError:
    Client = None

app = Flask(__name__)
print("Current Project:", os.path.abspath(os.getcwd()))
print("Template Folder:", app.template_folder)
print("App File:", __file__)

# Secret key for session signing — replace in production
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_please_change')

# Flask-Mail configuration for password reset OTP
# Replace the placeholder values below with your Gmail address and app password.
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True

app.config['MAIL_USERNAME'] = 'bhimasiambiger501@gmail.com'
app.config['MAIL_PASSWORD'] = 'wgubxjfknwsloqdi'
app.config['MAIL_DEFAULT_SENDER'] = 'bhimasiambiger501@gmail.com'
mail = Mail(app)

TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID', '')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN', '')
TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER', '')

@app.before_request
def protect_routes():
    public_routes = {"home", "login", "register", "register_user", "forgot_password", "verify_otp", "reset_password", "static"}

    if request.endpoint is None:
        return None

    if request.endpoint in public_routes:
        return None

    if request.path.startswith("/static/"):
        return None

    if "username" not in session:
        return redirect(url_for("login"))

    return None

APP_DATA = os.path.join(os.getenv("LOCALAPPDATA") or os.path.dirname(__file__), "AI_NIDS")
os.makedirs(APP_DATA, exist_ok=True)

DB_PATH = os.environ.get("NIDS_DB_PATH") or os.path.join(APP_DATA, "users.db")

# ---------------------- DATABASE ----------------------

def init_db():
    # Ensure the DB file is writable. On Windows OneDrive the file can be marked readonly.
    global DB_PATH
    try:
        if os.path.exists(DB_PATH) and not os.access(DB_PATH, os.W_OK):
            try:
                os.chmod(DB_PATH, stat.S_IWRITE | stat.S_IREAD)
            except Exception:
                pass
    except Exception:
        pass

    try:
        conn = sqlite3.connect(DB_PATH)
    except sqlite3.OperationalError as e:
        # Could be a readonly file on OneDrive or permission issue. Fall back to a local writable DB.
        alt = os.path.join(os.path.dirname(__file__), "users_local.db")
        try:
            conn = sqlite3.connect(alt)
            DB_PATH = alt
        except Exception:
            raise

    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    users_table_exists = cursor.fetchone() is not None
    needs_schema_migration = False

    if users_table_exists:
        cursor.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cursor.fetchall()]
        if "phone" not in columns:
            needs_schema_migration = True
            cursor.execute("DROP TABLE IF EXISTS users_old")
            cursor.execute("ALTER TABLE users RENAME TO users_old")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullname TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
    """)

    if needs_schema_migration:
        cursor.execute("""
        INSERT INTO users(id, fullname, email, phone, username, password)
        SELECT id, fullname, email, 'phone_' || id, username, password
        FROM users_old
        """)
        cursor.execute("DROP TABLE users_old")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings(
        id INTEGER PRIMARY KEY CHECK (id = 1),
        dark_mode INTEGER DEFAULT 1,
        auto_start_monitoring INTEGER DEFAULT 1,
        network_interface TEXT DEFAULT 'All Interfaces',
        capture_filter TEXT DEFAULT 'All',
        ai_detection INTEGER DEFAULT 1,
        detection_sensitivity TEXT DEFAULT 'Medium',
        desktop_notification INTEGER DEFAULT 1,
        sound_alert INTEGER DEFAULT 0,
        email_alerts INTEGER DEFAULT 0,
        refresh_interval TEXT DEFAULT '3 Seconds'
    )
    """)

    cursor.execute("INSERT OR IGNORE INTO settings (id) VALUES (1)")

    conn.commit()
    conn.close()

init_db()

# ---------------------- PACKET STORAGE ----------------------

packets = []

# ---------------------- PACKET CAPTURE ----------------------

def infer_packet_risk(packet_info, packet):
    features = extract_features(packet)

    if not features:
        return packet_info

    score = 0
    packet_length = features.get("packet_length", 0)
    dst_port = features.get("dst_port", 0)
    protocol = packet_info.get("protocol", "OTHER")

    if packet_length > 1500:
        score += 20
    if packet_length > 5000:
        score += 30

    if protocol == "UDP":
        score += 8
    elif protocol == "TCP":
        score += 4

    if dst_port in {22, 23, 3389, 21}:
        score += 20
    elif dst_port in {80, 443}:
        score += 2

    if packet.haslayer(TCP):
        flags = int(packet[TCP].flags)
        if flags == 0x02:
            score += 10

    if score >= 50:
        packet_info["prediction"] = "ATTACK"
        packet_info["status"] = "THREAT"
    elif score >= 25:
        packet_info["prediction"] = "SUSPICIOUS"
        packet_info["status"] = "ALERT"
    else:
        packet_info["prediction"] = "BENIGN"
        packet_info["status"] = "SAFE"

    packet_info["risk_score"] = score
    return packet_info


def build_detection_summary(packet_list):
    total_packets = len(packet_list)
    safe_count = sum(1 for entry in packet_list if str(entry.get("status", "SAFE")).upper() == "SAFE")
    alert_count = sum(1 for entry in packet_list if str(entry.get("status", "SAFE")).upper() == "ALERT")
    threat_count = sum(1 for entry in packet_list if str(entry.get("status", "SAFE")).upper() == "THREAT")

    suspicious_packets = [entry for entry in packet_list if str(entry.get("status", "SAFE")).upper() != "SAFE"]
    latest_alerts = list(reversed(suspicious_packets[-5:]))

    attack_rate = round(((alert_count + threat_count) / total_packets) * 100, 1) if total_packets else 0.0

    return {
        "total_packets": total_packets,
        "safe_count": safe_count,
        "alert_count": alert_count,
        "threat_count": threat_count,
        "attack_rate": attack_rate,
        "latest_alerts": latest_alerts,
    }


def process_packet(packet):

    if packet.haslayer(IP):

        protocol = "OTHER"

        if packet.haslayer(TCP):
            protocol = "TCP"

        elif packet.haslayer(UDP):
            protocol = "UDP"

        packet_info = {
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "protocol": protocol,
            "length": len(packet),
            "prediction": "BENIGN",
            "status": "SAFE"
        }

        packet_info = infer_packet_risk(packet_info, packet)
        packets.append(packet_info)

        if len(packets) > 30:
            packets.pop(0)

def start_capture():
    sniff(prn=process_packet, store=False)


def send_reset_otp_email(email, otp):
    try:
        msg = Message(
            subject='AI NIDS Password Reset OTP',
            recipients=[email],
            body=f"Your OTP is:\n\n{otp}\n\nThis OTP is valid for 5 minutes.\n\nIf you didn't request this, ignore this email."
        )
        mail.send(msg)
        return True
    except Exception:
        return False


def _normalize_phone_number(phone):
    digits = ''.join(ch for ch in str(phone or '') if ch.isdigit())
    if not digits:
        return str(phone or '')
    if len(digits) == 10:
        return f'+91{digits}'
    if digits.startswith('91') and len(digits) == 12:
        return f'+{digits}'
    return f'+{digits}'


def send_reset_otp_sms(phone, otp):
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN or not TWILIO_PHONE_NUMBER:
        print("Twilio is not configured. SMS notification skipped.")
        return False, None

    if Client is None:
        print("Twilio package is not available. SMS notification skipped.")
        return False, None

    try:
        normalized_phone = _normalize_phone_number(phone)
        print(f"Sending Twilio SMS to: {normalized_phone}")
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=f"AI NIDS Password Reset\n\nYour OTP is:\n\n{otp}\n\nValid for 5 minutes.",
            from_=TWILIO_PHONE_NUMBER,
            to=normalized_phone,
        )
        print("Twilio Message SID:", getattr(message, 'sid', 'N/A'))
        print("Twilio API response:", message)
        print("SMS sent successfully")
        print("Message SID:", message.sid)
        print("Status:", message.status)
        print("To:", message.to)
        print("From:", message.from_)
        return True, message
    except Exception as exc:
        print("Twilio SMS send failed.")
        print("Exception type:", type(exc).__name__)
        print("Exception details:", repr(exc))
        print("If this is a Twilio trial account, ensure the destination number is verified.")
        return False, None


# ---------------------- HOME ----------------------

@app.route("/")
def home():
    return redirect(url_for("login"))

# ---------------------- LOGIN ----------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        success = session.pop("password_reset_success", None)
        return render_template("login.html", success=success)

    username = request.form["username"]
    password = request.form["password"]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    )

    user = cursor.fetchone()

    conn.close()

    if user:
        session['username'] = username
        return redirect(url_for("dashboard"))

    return render_template(
        "login.html",
        error="❌ Invalid Username or Password"
    )

# ---------------------- FORGOT PASSWORD ----------------------
@app.route("/face_verify")
def face_verify():

    if "reset_user_id" not in session:
        return redirect(url_for("forgot_password"))

    return render_template("face_verify.html")


@app.route("/verify_face", methods=["POST"])
def verify_face():

    try:
        data = request.get_json()

        if not data or "image" not in data:
            return jsonify({
                "success": False,
                "message": "No image received."
            })

        image_data = data["image"]

        if "," in image_data:
            image_data = image_data.split(",", 1)[1]

        image_bytes = base64.b64decode(image_data)

        image_array = np.frombuffer(
            image_bytes,
            dtype=np.uint8
        )

        frame = cv2.imdecode(
            image_array,
            cv2.IMREAD_COLOR
        )

        if frame is None:
            return jsonify({
                "success": False,
                "message": "Invalid image."
            })

        gray = cv2.cvtColor(
            frame,
            cv2.COLOR_BGR2GRAY
        )

        faces = face_cascade.detectMultiScale(
            gray,
            scaleFactor=1.1,
            minNeighbors=5,
            minSize=(80, 80)
        )

        if len(faces) == 0:

            return jsonify({
                "success": False,
                "message": "No face detected. Please position your face inside the frame."
            })

        if len(faces) > 1:

            return jsonify({
                "success": False,
                "message": "Multiple faces detected. Please make sure only your face is visible."
            })

        session["face_verified"] = True

        return jsonify({
            "success": True,
            "message": "Face detected successfully.",
            "redirect": url_for("send_reset_otp")
        })

    except Exception as exc:

        print("Face verification error:", repr(exc))

        return jsonify({
            "success": False,
            "message": "Face verification failed."
        })


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():

    # YOUR EXISTING FORGOT PASSWORD CODE GOES HERE
    
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        recovery_type = request.form.get("recovery_type", "email")
        recovery_value = request.form.get("recovery_value", "").strip()

        if recovery_type == "phone":
            recovery_value = recovery_value.strip()
        else:
            recovery_value = recovery_value.strip().lower()

        if not recovery_value:
            return render_template(
                "forgot_password.html",
                error="❌ Enter your registered email or phone number.",
                recovery_type=recovery_type,
            )

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        if recovery_type == "phone":
            cursor.execute("SELECT id, phone FROM users WHERE phone=?", (recovery_value,))
        else:
            cursor.execute("SELECT id, email FROM users WHERE email=?", (recovery_value,))

        user = cursor.fetchone()
        conn.close()

        if not user:
            return render_template(
                "forgot_password.html",
                error="Data not registered.",
                alert_message="Data not registered.",
                recovery_type=recovery_type,
                recovery_value=recovery_value,
            )

        otp = f"{random.randint(100000,999999):06d}"

        session["reset_user_id"] = user[0]
        session["reset_target"] = recovery_value
        session["reset_method"] = recovery_type
        session["otp"] = otp
        session["otp_expiry"] = (
            datetime.utcnow() + timedelta(minutes=10)
        ).strftime("%Y-%m-%d %H:%M:%S")

        if recovery_type == "phone":
            send_reset_otp_sms(recovery_value, otp)
        else:
            try:
                send_reset_otp_email(recovery_value, otp)
                print("OTP sent successfully")
            except Exception as e:
                print("Email Error:", e)
                return render_template(
                    "forgot_password.html",
                    error=f"Email Error: {e}",
                    recovery_type=recovery_type,
                    recovery_value=recovery_value,
                )

        return redirect(url_for("verify_otp"))

    return render_template("forgot_password.html")

@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()
        reset_user_id = session.get("reset_user_id")
        reset_target = session.get("reset_target")
        stored_otp = session.get("otp")
        expiry = session.get("otp_expiry")

        if not reset_user_id or not reset_target or not stored_otp or not expiry:
            return render_template("verify_otp.html", error="❌ Session expired. Please try again.")

        try:
            expires_at = datetime.strptime(expiry, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return render_template("verify_otp.html", error="❌ Session expired. Please try again.")

        if datetime.utcnow() > expires_at:
            session.pop("reset_user_id", None)
            session.pop("reset_target", None)
            session.pop("reset_method", None)
            session.pop("otp", None)
            session.pop("otp_expiry", None)
            return render_template("verify_otp.html", error="❌ OTP expired.")

        if entered_otp != stored_otp:
            return render_template("verify_otp.html", error="❌ Invalid OTP.")

        return redirect(url_for("reset_password"))

    return render_template("verify_otp.html")


@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        reset_user_id = session.get("reset_user_id")

        if not reset_user_id:
            return render_template("reset_password.html", error="❌ Session expired. Please try again.")

        if new_password != confirm_password:
            return render_template("reset_password.html", error="❌ Passwords do not match.")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password=? WHERE id=?", (new_password, reset_user_id))
        conn.commit()
        conn.close()

        session.pop("reset_user_id", None)
        session.pop("reset_target", None)
        session.pop("reset_method", None)
        session.pop("otp", None)
        session.pop("otp_expiry", None)
        session["password_reset_success"] = "✅ Password reset successfully."

        return redirect(url_for("login"))

    return render_template("reset_password.html")


# ---------------------- REGISTER ----------------------

@app.route("/register")
def register():
    return render_template("register.html")

@app.route("/register", methods=["POST"])
def register_user():
    global DB_PATH
    fullname = request.form.get("fullname", "").strip()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    if not (fullname and email and phone and username and password and confirm):
        return render_template("register.html", error="❌ All fields are required.")

    if password != confirm:
        return render_template("register.html", error="❌ Passwords do not match.")

    # If the configured DB is not writable (OneDrive lock), fall back to a local writable DB.
    conn = None
    try:
        if os.path.exists(DB_PATH) and not os.access(DB_PATH, os.W_OK):
            alt = os.path.join(os.path.dirname(__file__), "users.db")
            try:
                # Ensure the alt DB exists and has the users table
                tmpc = sqlite3.connect(alt)
                tmpc.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        fullname TEXT NOT NULL,
                        email TEXT NOT NULL,
                        phone TEXT NOT NULL,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL
                    )
                    """
                )
                tmpc.commit()
                tmpc.close()
                DB_PATH = alt
            except Exception:
                pass
    except Exception:
        pass
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT 1 FROM users WHERE username=?", (username,))
        if cursor.fetchone():\
            return render_template("register.html", error="❌ Username already exists.")



        cursor.execute(
            "INSERT INTO users(fullname,email,phone,username,password) VALUES(?,?,?,?,?)",
            (fullname, email, phone, username, password),
        )

        conn.commit()
    
    except Exception as e:
        # If the error indicates the DB is readonly, try falling back to a local DB and retry once.
        msg = str(e).lower()
        if isinstance(e, sqlite3.OperationalError) and "readonly" in msg:
            alt = os.path.join(os.path.dirname(__file__), "users.db")
            try:
                tmpc = sqlite3.connect(alt)
                tmpc.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        fullname TEXT NOT NULL,
                        email TEXT NOT NULL,
                        phone TEXT NOT NULL,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL
                    )
                    """
                )
                tmpc.commit()
                tmpc.close()
                DB_PATH = alt

                # Retry insert once
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM users WHERE username=?", (username,))
                if cursor.fetchone():
                    return render_template("register.html", error="❌ Username already exists.")
                cursor.execute("SELECT 1 FROM users WHERE email=?", (email,))
                if cursor.fetchone():
                    return render_template("register.html", error="❌ Email already exists.")
                cursor.execute("SELECT 1 FROM users WHERE phone=?", (phone,))
                if cursor.fetchone():
                    return render_template("register.html", error="❌ Phone number already exists.")
                cursor.execute(
                    "INSERT INTO users(fullname,email,phone,username,password) VALUES(?,?,?,?,?)",
                    (fullname, email, phone, username, password),
                )
                conn.commit()
                conn.close()
                return redirect(url_for("home"))
            except Exception as e2:
                return render_template("register.html", error=f"❌ Registration failed: {e2}")

        return render_template("register.html", error=f"❌ Registration failed: {e}")
    finally:
        if conn:
            conn.close()

    return redirect(url_for("home"))

# ---------------------- DASHBOARD ----------------------

@app.route("/dashboard")
def dashboard():
    return render_template("index.html", active_page="dashboard")

# ---------------------- ANALYTICS ----------------------

@app.route("/analytics")
def analytics():
    return render_template("analytics.html", active_page="analytics")

@app.route("/logs")
def logs():
    return render_template("Logs.html", active_page="logs", packets=packets)

@app.route("/reports")
def reports():
    return render_template("reports.html", active_page="reports")

# ---------------------- AI DETECTION ----------------------

@app.route("/ai_detection")
def ai_detection():
    return render_template("ai_detection.html", active_page="ai_detection")

@app.route("/ai_detection_summary")
def ai_detection_summary():
    return jsonify(build_detection_summary(packets))

# ---------------------- SETTINGS ----------------------

@app.route("/settings", methods=["GET", "POST"])
def settings():

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    message = ""

    if request.method == "POST":

        dark_mode = 1 if request.form.get("dark_mode") else 0
        auto_start = 1 if request.form.get("auto_start_monitoring") else 0
        network_interface = request.form["network_interface"]
        capture_filter = request.form["capture_filter"]
        ai_detection = 1 if request.form.get("ai_detection") else 0
        detection_sensitivity = request.form["detection_sensitivity"]
        desktop_notification = 1 if request.form.get("desktop_notification") else 0
        sound_alert = 1 if request.form.get("sound_alert") else 0
        email_alerts = 1 if request.form.get("email_alerts") else 0
        refresh_interval = request.form["refresh_interval"]

        cursor.execute("""
        UPDATE settings SET

        dark_mode=?,
        auto_start_monitoring=?,
        network_interface=?,
        capture_filter=?,
        ai_detection=?,
        detection_sensitivity=?,
        desktop_notification=?,
        sound_alert=?,
        email_alerts=?,
        refresh_interval=?

        WHERE id=1
        """,
        (
            dark_mode,
            auto_start,
            network_interface,
            capture_filter,
            ai_detection,
            detection_sensitivity,
            desktop_notification,
            sound_alert,
            email_alerts,
            refresh_interval
        ))

        conn.commit()
        message = "✅ Settings Saved Successfully"

    cursor.execute("SELECT * FROM settings WHERE id=1")
    settings = cursor.fetchone()

    conn.close()

    return render_template(
        "settings.html",
        settings=settings,
        message=message,
        active_page="settings"
    )

# ---------------------- CHANGE USERNAME ----------------------

@app.route("/change_username", methods=["GET", "POST"])
def change_username():

    if request.method=="POST":

        old=request.form["old_username"]
        new=request.form["new_username"]

        conn=sqlite3.connect(DB_PATH)
        cursor=conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=?",
            (old,)
        )

        user=cursor.fetchone()

        if not user:
            conn.close()
            return render_template(
                "change_username.html",
                error="❌ Old username not found."
            )

        cursor.execute(
            "UPDATE users SET username=? WHERE username=?",
            (new,old)
        )

        conn.commit()
        conn.close()

        return render_template(
            "change_username.html",
            success="✅ Username Updated Successfully."
        )

    return render_template("change_username.html")

# ---------------------- CHANGE PASSWORD ----------------------

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        username = session.get("username")
        if not username:
            return redirect(url_for("login"))

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password FROM users WHERE username=?",
            (username,)
        )
        user = cursor.fetchone()

        if not user or user[0] != current_password:
            conn.close()
            return render_template(
                "change_password.html",
                error="❌ Current password is incorrect."
            )

        if new_password != confirm_password:
            conn.close()
            return render_template(
                "change_password.html",
                error="❌ New passwords do not match."
            )

        if not new_password:
            conn.close()
            return render_template(
                "change_password.html",
                error="❌ New password cannot be empty."
            )

        cursor.execute(
            "UPDATE users SET password=? WHERE username=?",
            (new_password, username)
        )
        conn.commit()
        conn.close()

        return render_template(
            "change_password.html",
            success="✅ Password changed successfully."
        )

    return render_template("change_password.html")

# ---------------------- LIVE CAPTURE ----------------------

@app.route("/live_capture")
def live_capture():
    return render_template("live_capture.html", active_page="live_capture")

# ---------------------- NETWORK DEVICES ----------------------

def build_device_view_data():
    device_map = {}
    packet_list = packets if isinstance(packets, list) else []

    for packet in packet_list:
        if not isinstance(packet, dict):
            packet = {}

        src_ip = packet.get("src") or packet.get("source") or "Unknown Device"
        dst_ip = packet.get("dst") or packet.get("destination") or "Unknown Device"

        for ip_address, direction in ((src_ip, "sent"), (dst_ip, "received")):
            entry = device_map.setdefault(
                ip_address,
                {
                    "name": "Unknown Device",
                    "ip": ip_address,
                    "mac": "Unknown MAC",
                    "status": "Online",
                    "last_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                    "packets_sent": 0,
                    "packets_received": 0,
                    "suspicious": False,
                },
            )
            entry["status"] = "Online"
            entry["last_seen"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            if direction == "sent":
                entry["packets_sent"] += 1
            else:
                entry["packets_received"] += 1

            if str(packet.get("status", "SAFE")).upper() != "SAFE":
                entry["suspicious"] = True

    device_list = []
    for ip_address, entry in device_map.items():
        device_list.append(
            {
                "name": entry.get("name", "Unknown Device"),
                "ip": entry.get("ip", ip_address),
                "mac": entry.get("mac", "Unknown MAC"),
                "status": entry.get("status", "Online"),
                "last_seen": entry.get("last_seen", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
                "packets_sent": entry.get("packets_sent", 0),
                "packets_received": entry.get("packets_received", 0),
                "suspicious": entry.get("suspicious", False),
            }
        )

    device_list.sort(key=lambda item: item["ip"])

    return {
        "devices": device_list,
        "total_devices": len(device_list),
        "online_devices": sum(1 for item in device_list if item["status"] == "Online"),
        "suspicious_devices": sum(1 for item in device_list if item["suspicious"]),
    }


@app.route("/devices")
def devices():
    return render_template("devices.html", active_page="network_devices", **build_device_view_data())


@app.route("/network_devices")
def network_devices():
    return render_template("network_devices.html", active_page="network_devices", **build_device_view_data())

# ---------------------- USER PROFILE ----------------------

@app.route("/profile")
def profile():
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT fullname, email, username FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return redirect(url_for("login"))

    login_time = session.get("login_time")
    if not login_time:
        login_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        session["login_time"] = login_time

    last_login = session.get("last_login") or login_time
    if not session.get("last_login"):
        session["last_login"] = login_time

    role = "Administrator" if str(username).lower() == "admin" else "User"

    return render_template(
        "profile.html",
        user=user,
        role=role,
        login_time=login_time,
        last_login=last_login,
        active_page="profile",
    )

# ---------------------- PACKETS API ----------------------

@app.route("/packets")
def get_packets():
    return jsonify(packets)

# ---------------------- LOGOUT ----------------------

@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for("home"))

# ---------------------- MAIN ----------------------

if __name__ == "__main__":

    threading.Thread(
        target=start_capture,
        daemon=True
    ).start()

    threading.Timer(
        2,
        lambda: webbrowser.open("http://127.0.0.1:5000/login")
    ).start()

    app.run(debug=False)