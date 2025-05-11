from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import threading
import time

app = Flask(__name__)

# ========== API KEY SYSTEM ==========
API_KEYS = {
    "devthesuperior1234": {"remaining": 30, "total": 30, "created_at": time.time()},
}

MASTER_KEY = "devthesuperiorontopbxby"
keys_lock = threading.Lock()

def check_api_key(key, deduct=True):
    with keys_lock:
        if key not in API_KEYS:
            return False, "Invalid API key"
        
        if API_KEYS[key]["remaining"] <= 0:
            return False, "No remaining requests"
        
        if deduct:
            API_KEYS[key]["remaining"] -= 1
        return True, API_KEYS[key]["remaining"]

@app.route('/key/add', methods=['POST'])
def add_key():
    master_key = request.args.get("master_key")
    new_key = request.args.get("new_key")
    limit = request.args.get("limit", default=100, type=int)
    
    if not master_key or master_key != MASTER_KEY:
        return jsonify({"error": "Invalid master key"}), 403
    
    if not new_key:
        return jsonify({"error": "new_key is required"}), 400
    
    with keys_lock:
        if new_key in API_KEYS:
            return jsonify({"error": "Key already exists"}), 400
        
        API_KEYS[new_key] = {
            "remaining": limit,
            "total": limit,
            "created_at": time.time()
        }
    
    return jsonify({
        "message": "Key added successfully",
        "key": new_key,
        "limit": limit
    }), 200

@app.route('/key/reset', methods=['POST'])
def reset_key():
    master_key = request.args.get("master_key")
    key = request.args.get("key")
    new_limit = request.args.get("new_limit", type=int)
    
    if not master_key or master_key != MASTER_KEY:
        return jsonify({"error": "Invalid master key"}), 403
    
    if not key:
        return jsonify({"error": "key is required"}), 400
    
    with keys_lock:
        if key not in API_KEYS:
            return jsonify({"error": "Key not found"}), 404
        
        if new_limit:
            API_KEYS[key]["total"] = new_limit
            API_KEYS[key]["remaining"] = new_limit
        else:
            API_KEYS[key]["remaining"] = API_KEYS[key]["total"]
    
    return jsonify({
        "message": "Key reset successfully",
        "key": key,
        "remaining": API_KEYS[key]["remaining"],
        "total": API_KEYS[key]["total"]
    }), 200

@app.route('/key/list', methods=['GET'])
def list_keys():
    master_key = request.args.get("master_key")
    
    if not master_key or master_key != MASTER_KEY:
        return jsonify({"error": "Invalid master key"}), 403
    
    with keys_lock:
        return jsonify({
            "keys": [{
                "key": k,
                "remaining": v["remaining"],
                "total": v["total"],
                "created_at": v["created_at"]
            } for k, v in API_KEYS.items()]
        }), 200

# ========== MAIN FUNCTIONALITY ==========
def load_tokens(server_name):
    try:
        if server_name == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        elif server_name in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        elif server_name == "EU":
            with open("token_eu.json", "r") as f:
                tokens = json.load(f)
        elif server_name == "VN":
            with open("token_vn.json", "r") as f:
                tokens = json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status code: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None
        tasks = []
        tokens = load_tokens(server_name)
        if tokens is None:
            app.logger.error("Failed to load tokens.")
            return None
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False)
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decoding returned None.")
        return decode
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    api_key = request.args.get("key")
    
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400
    
    # First verify key without deducting
    is_valid, remaining = check_api_key(api_key, deduct=False)
    if not is_valid:
        return jsonify({"error": remaining}), 403
    
    try:
        def process_request():
            tokens = load_tokens(server_name)
            if tokens is None:
                raise Exception("Failed to load tokens.")
            token = tokens[0]['token']
            encrypted_uid = enc(uid)
            if encrypted_uid is None:
                raise Exception("Encryption of UID failed.")

            before = make_request(encrypted_uid, server_name, token)
            if before is None:
                raise Exception("Failed to retrieve initial player info.")
            try:
                jsone = MessageToJson(before)
            except Exception as e:
                raise Exception(f"Error converting 'before' protobuf to JSON: {e}")
            data_before = json.loads(jsone)
            before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
            try:
                before_like = int(before_like)
            except Exception:
                before_like = 0
            app.logger.info(f"Likes before command: {before_like}")

            if server_name == "IND":
                url = "https://client.ind.freefiremobile.com/LikeProfile"
            elif server_name in {"BR", "US", "SAC", "NA"}:
                url = "https://client.us.freefiremobile.com/LikeProfile"
            else:
                url = "https://clientbp.ggblueshark.com/LikeProfile"

            asyncio.run(send_multiple_requests(uid, server_name, url))

            after = make_request(encrypted_uid, server_name, token)
            if after is None:
                raise Exception("Failed to retrieve player info after like requests.")
            try:
                jsone_after = MessageToJson(after)
            except Exception as e:
                raise Exception(f"Error converting 'after' protobuf to JSON: {e}")
            data_after = json.loads(jsone_after)
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_uid = int(data_after.get('AccountInfo', {}).get('UID', 0))
            player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
            like_given = after_like - before_like
            
            if like_given != 0:
                status = 1
                message = "Success"
                # Only deduct if likes were actually given
                _, remaining = check_api_key(api_key, deduct=True)
            else:
                status = 2
                message = "Provided UID Already Received 100 Likes For Today So The Key Remaining Requests Didn't Decrease"
                # Get current count without deducting
                _, remaining = check_api_key(api_key, deduct=False)

            result = {
                "LikesGivenByAPI": like_given,
                "LikesbeforeCommand": before_like,
                "LikesafterCommand": after_like,
                "PlayerNickname": player_name,
                "UID": player_uid,
                "status": status,
                "remaining_requests": remaining,
                "message": message
            }
            return result

        result = process_request()
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
