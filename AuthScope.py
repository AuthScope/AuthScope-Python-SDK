
import os
import json
import time
import hashlib
import platform
from pathlib import Path
from datetime import datetime, timezone

import requests
import win32security

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature


class others:
    @staticmethod
    def get_hwid():
        if platform.system() == "Windows":
            user = os.getlogin()
            sid = win32security.LookupAccountName(None, user)[0]
            return hashlib.md5(
                win32security.ConvertSidToStringSid(sid).encode()
            ).hexdigest()
        return "unsupported"


class _crypto:
    def __init__(self, public_key_b64: str):
        pem = (
            "-----BEGIN PUBLIC KEY-----\n"
            f"{public_key_b64}\n"
            "-----END PUBLIC KEY-----"
        )
        self.key = load_pem_public_key(pem.encode())

    def verify(self, payload: dict, signature_hex: str) -> bool:
        try:
            sec = payload["security"]

            body = json.dumps(
                {k: v for k, v in payload.items() if k != "security"},
                separators=(",", ":"),
            ).encode()

            signed = (
                body
                + b"||"
                + str(sec["timestamp"]).encode()
                + b"||"
                + bytes.fromhex(sec["nonce"])
            )

            self.key.verify(
                bytes.fromhex(signature_hex),
                signed,
                ec.ECDSA(hashes.SHA256()),
            )
            return True

        except (InvalidSignature, KeyError, ValueError):
            return False

class _offline:
    def __init__(self, path: Path, days=7):
        self.path = path
        self.max_age = days * 86400

    def save(self, data: dict):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(data, f)

    def load(self):
        if not self.path.exists():
            return None
        with open(self.path) as f:
            return json.load(f)

class AuthClient:

    sessionid = None
    initialized = False
    offline_mode = False

    class user_data_class:
        def __init__(self):
            self.user_id = None
            self.username = None
            self.subscription = None
            self.created_at = None
            self.last_login = None
            self.client_ip = None

    user_data = user_data_class()

    def __init__(self, appID, version, publicKey, base_url=None):
        self.appID = appID
        self.version = version
        self.base_url = (
            base_url.rstrip("/")
            if base_url
            else "https://auth-scope.onrender.com/api/authenticate"
        )

        self.crypto = _crypto(publicKey)
        self.cache = _offline(
            Path.home() / ".authscope_cache" / f"{appID}.json"
        )

        self.init()

    def __normalize_user(self, raw: dict) -> dict:
        return {
            "user_id": raw.get("user_id"),
            "username": raw.get("username"),
            "created_at": raw.get("created_at"),
            "last_login": raw.get("last_login"),
            "subscription": raw.get("subscription"),
            "client_ip": raw.get("client_ip"),
        }

    def __apply_user(self, data):
        for k in vars(self.user_data):
            if k in data:
                setattr(self.user_data, k, data[k])

    def __request(self, route, payload):
        url = f"{self.base_url}{route}/{self.appID}"

        r = requests.post(url, json=payload, timeout=5)
        sig = r.headers.get("X-Signature")
        data = r.json()

        if not sig or not self.crypto.verify(data, sig):
            print("Signature verification failed")
            time.sleep(2)
            os._exit(1)

        if not data.get("success", True):
            print(data.get("message", "Server error"))
            time.sleep(2)
            os._exit(1)

        return data

    def __offline_login(self):
        cached = self.cache.load()
        if not cached:
            print("No offline login available")
            os._exit(1)

        data = cached.get("data")
        signature = cached.get("signature")

        if not data or not signature:
            print("Invalid offline cache")
            os._exit(1)

        if not self.crypto.verify(data, signature):
            print("Offline signature invalid")
            os._exit(1)

        cache_version = data.get("app_version")
        if not cache_version:
            print("Offline cache missing app version")
            os._exit(1)

        if cache_version != self.version:
            print(
                f"Offline cache version mismatch "
                f"(cache={cache_version}, app={self.version})"
            )
            os._exit(1)

        now = int(time.time())
        issued = int(str(data["security"]["timestamp"]))

        if now + 300 < issued:
            print("System clock rollback detected")
            os._exit(1)

        offline_until = data.get("offline_expires_at")
        if offline_until and now > int(offline_until):
            print("Offline access expired")
            os._exit(1)

        if now - issued > self.cache.max_age:
            print("Offline login expired")
            os._exit(1)

        created_at = datetime.fromisoformat(
            data["created_at"]
        ).replace(tzinfo=timezone.utc)

        if abs(created_at.timestamp() - issued) > 120:
            print("Timestamp inconsistency detected")
            os._exit(1)

        if data.get("HWID") != others.get_hwid():
            print("HWID mismatch")
            os._exit(1)

        self.__apply_user(self.__normalize_user(data))
        self.offline_mode = True
        return data

    def init(self):
        if self.initialized:
            return

        try:
            data = self.__request(
                "/init",
                {
                    "version": self.version,
                    "hwid": others.get_hwid(),
                },
            )

            self.sessionid = data.get("session_token")
            self.initialized = True
            self.offline_mode = False

        except requests.exceptions.ConnectionError:
            self.__offline_login()

    def license(self, key):
        try:
            data = self.__request(
                "/license-login",
                {
                    "license_key": key,
                    "session_token": self.sessionid,
                    "hwid": others.get_hwid(),
                },
            )

            if "offline_login_data" in data:
                self.cache.save(data["offline_login_data"])

            merged = {}

            if "user" in data:
                merged.update(data["user"])

            merged["subscription"] = data.get("subscription")
            merged["client_ip"] = data.get("client_ip")

            self.__apply_user(self.__normalize_user(merged))
            self.offline_mode = False
            print("Login successful")

        except requests.exceptions.ConnectionError:
            self.__offline_login()

    def user_login(self, username, password):
        try:
            data = self.__request(
                "/user-login",
                {
                    "username": username,
                    "password": password,
                    "session_token": self.sessionid,
                    "hwid": others.get_hwid(),
                },
            )

            if "offline_login_data" in data:
                self.cache.save(data["offline_login_data"])

            merged = {}

            if "user" in data:
                merged.update(data["user"])

            merged["subscription"] = data.get("subscription")
            merged["client_ip"] = data.get("client_ip")

            self.__apply_user(self.__normalize_user(merged))
            self.offline_mode = False
            print("Login successful")

        except requests.exceptions.ConnectionError:
            self.__offline_login()

    def register(self, username, password):
        try:
            payload = {
                "username": username,
                "password": password,
                "session_token": self.sessionid,
                "hwid": others.get_hwid(),
            }
            
            data = self.__request(
                "/register",
                payload,
            )

            merged = {}

            if "user" in data:
                merged.update(data["user"])

            merged["subscription"] = data.get("subscription")
            merged["client_ip"] = data.get("client_ip")

            self.__apply_user(self.__normalize_user(merged))
            self.offline_mode = False
            print("Registration successful")
            return data

        except requests.exceptions.ConnectionError:
            print("Registration failed: No connection to server")
            time.sleep(2)
            os._exit(1)

    def validate_session(self):
        try:
            data = self.__request(
                "/validate-session",
                {
                    "session_token": self.sessionid,
                    "hwid": others.get_hwid(),
                },
            )

            is_valid = data.get("valid", False)
            
            if is_valid:
                merged = {}

                if "user" in data:
                    merged.update(data["user"])

                merged["subscription"] = data.get("subscription")
                merged["client_ip"] = data.get("client_ip")

                self.__apply_user(self.__normalize_user(merged))
                print("Session is valid")

            return is_valid

        except requests.exceptions.ConnectionError:
            print("Could not validate session: No connection to server")
            return False

    def upgrade(self, subscription_plan):
        try:
            data = self.__request(
                "/upgrade",
                {
                    "subscription_plan": subscription_plan,
                    "session_token": self.sessionid,
                    "hwid": others.get_hwid(),
                },
            )

            merged = {}

            if "user" in data:
                merged.update(data["user"])

            merged["subscription"] = data.get("subscription")
            merged["client_ip"] = data.get("client_ip")

            self.__apply_user(self.__normalize_user(merged))
            print(f"Upgrade to {subscription_plan} successful")
            return data

        except requests.exceptions.ConnectionError:
            print("Upgrade failed: No connection to server")
            time.sleep(2)
            os._exit(1)

    def logout(self):
        try:
            self.__request(
                "/logout",
                {
                    "session_token": self.sessionid,
                    "hwid": others.get_hwid(),
                },
            )
        except requests.exceptions.ConnectionError:
            pass

        self.sessionid = None
        self.initialized = False
        self.offline_mode = False

        for k in vars(self.user_data):
            setattr(self.user_data, k, None)

        print("Logged out")



def display_menu():
    print("\n=== AuthScope Demo ===")
    print("1. Register New Account")
    print("2. Login with Credentials")
    print("3. Login with License Key")
    print("4. View User Info")
    print("5. Validate Session")
    print("6. Upgrade Subscription")
    print("7. Logout")
    print("8. Exit")
    return input("Choose option: ")


def main():
    # Initialize the client
    auth = AuthClient(
        appID="your_app_id",
        version="1.0.0",
        publicKey="your_public_key_string",
    )
    
    # Check offline mode
    if auth.offline_mode:
        print("⚠️  Running in OFFLINE MODE - using cached credentials")
        print(f"Welcome back {auth.user_data.username}!\n")
    
    while True:
        choice = display_menu()
        
        try:
            if choice == "1":
                # Register
                print("\n--- Register New Account ---")
                username = input("Create username: ")
                password = input("Create password: ")
                
                auth.register(
                    username=username,
                    password=password,
                )
                print("✓ Registration successful!")
            
            elif choice == "2":
                # User Login
                print("\n--- User Login ---")
                username = input("Username: ")
                password = input("Password: ")
                
                auth.user_login(username, password)
                print("✓ Login successful!")
            
            elif choice == "3":
                # License Login
                print("\n--- License Login ---")
                license_key = input("Enter license key: ")
                
                auth.license(license_key)
                print("✓ License login successful!")
            
            elif choice == "4":
                # View User Info
                print("\n--- User Information ---")
                print(f"Username: {auth.user_data.username}")
                print(f"User ID: {auth.user_data.user_id}")
                print(f"Subscription: {auth.user_data.subscription}")
                print(f"Client IP: {auth.user_data.client_ip}")
                print(f"Created: {auth.user_data.created_at}")
                print(f"Last Login: {auth.user_data.last_login}")
                print(f"Offline Mode: {auth.offline_mode}")
            
            elif choice == "5":
                # Validate Session
                print("\n--- Session Validation ---")
                is_valid = auth.validate_session()
                if is_valid:
                    print("✓ Session is valid")
                else:
                    print("✗ Session is invalid or expired")
            
            elif choice == "6":
                # Upgrade Subscription
                print("\n--- Subscription Upgrade ---")
                print("Available plans: free, basic, premium, enterprise")
                plan = input("Choose subscription plan: ")
                
                auth.upgrade(plan)
                print(f"✓ Upgraded to {plan}!")
            
            elif choice == "7":
                # Logout
                auth.logout()
                print("✓ Logged out successfully!")
            
            elif choice == "8":
                # Exit
                auth.logout()
                print("Goodbye!")
                break
            
            else:
                print("Invalid option")
        
        except KeyboardInterrupt:
            print("\n\nInterrupted by user")
            auth.logout()
            break
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    main()
