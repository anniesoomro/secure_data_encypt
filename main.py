import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

# Set page config (must be first)
st.set_page_config(
    page_title="Secure Data Vault",
    page_icon="🔒",
    layout="centered"
)

# Security Constants
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes
DATA_FILE = "secure_data.json"

# Generate encryption key
def get_fernet_key():
    salt = b'fixed_salt_'  # Should be unique per user in production
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(b"master_secret_key"))  # Change in production

KEY = get_fernet_key()
cipher = Fernet(KEY)

# Initialize session state
if 'auth' not in st.session_state:
    st.session_state.auth = {
        'failed_attempts': 0,
        'lockout_time': 0,
        'authenticated': False,
        'current_user': None
    }

# Data Management
def load_data():
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE) as f:
                return json.load(f)
    except:
        return {}
    return {}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

stored_data = load_data()

# Security Functions
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    hashed = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return hashed, salt

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# UI Helpers
def show_error(message):
    st.error(f"❌ {message}")

def show_success(message):
    st.success(f"✅ {message}")

def is_locked_out():
    if st.session_state.auth['failed_attempts'] >= MAX_ATTEMPTS:
        current_time = time.time()
        if current_time - st.session_state.auth['lockout_time'] < LOCKOUT_TIME:
            remaining = int(LOCKOUT_TIME - (current_time - st.session_state.auth['lockout_time']))
            show_error(f"Account locked. Try again in {remaining} seconds.")
            return True
        else:
            st.session_state.auth['failed_attempts'] = 0
    return False

# Main App Interface
st.title("🔒 Secure Data Vault")
st.caption("Store and retrieve your sensitive data securely")

# Navigation
menu_options = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
if not st.session_state.auth['authenticated']:
    choice = st.sidebar.selectbox("Menu", ["Home", "Register", "Login"])
else:
    choice = st.sidebar.selectbox("Menu", menu_options)

# Page Routing
if choice == "Home":
    st.header("Welcome")
    st.write("""
    This app lets you securely store and retrieve sensitive data using:
    - Military-grade encryption (AES-128)
    - Secure passkey protection
    - Account lockout after 3 failed attempts
    """)
    
    if st.session_state.auth['authenticated']:
        show_success(f"Logged in as {st.session_state.auth['current_user']}")
        if st.button("Logout"):
            st.session_state.auth['authenticated'] = False
            st.session_state.auth['current_user'] = None
            st.rerun()

elif choice == "Register":
    st.header("Create Account")
    
    with st.form("register_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        confirm = st.text_input("Confirm Password", type="password")
        
        if st.form_submit_button("Register"):
            if not (username and password and confirm):
                show_error("All fields are required")
            elif password != confirm:
                show_error("Passwords don't match")
            elif username in stored_data:
                show_error("Username already exists")
            else:
                hashed_pw, salt = hash_passkey(password)
                stored_data[username] = {
                    "password": hashed_pw.decode(),
                    "salt": salt.hex(),
                    "entries": {}
                }
                save_data(stored_data)
                show_success("Account created! Please login")

elif choice == "Login":
    st.header("Login")
    
    if is_locked_out():
        st.stop()
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.form_submit_button("Login"):
            if username not in stored_data:
                show_error("User not found")
            else:
                user_data = stored_data[username]
                try:
                    salt = bytes.fromhex(user_data["salt"])
                    hashed_input, _ = hash_passkey(password, salt)
                    if hashed_input.decode() == user_data["password"]:
                        st.session_state.auth['authenticated'] = True
                        st.session_state.auth['current_user'] = username
                        st.session_state.auth['failed_attempts'] = 0
                        show_success("Login successful!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        raise ValueError("Invalid password")
                except:
                    st.session_state.auth['failed_attempts'] += 1
                    attempts_left = MAX_ATTEMPTS - st.session_state.auth['failed_attempts']
                    show_error(f"Wrong password! {attempts_left} attempts left")
                    
                    if st.session_state.auth['failed_attempts'] >= MAX_ATTEMPTS:
                        st.session_state.auth['lockout_time'] = time.time()
                        show_error("Too many attempts! Account locked for 5 minutes")

elif choice == "Store Data":
    if not st.session_state.auth['authenticated']:
        show_error("Please login first")
        time.sleep(1)
        st.rerun()
    
    st.header("Store New Data")
    
    with st.form("store_form"):
        entry_name = st.text_input("Entry name")
        secret_data = st.text_area("Your secret data", height=150)
        passkey = st.text_input("Encryption passkey", type="password")
        confirm = st.text_input("Confirm passkey", type="password")
        
        if st.form_submit_button("Encrypt & Save"):
            if not (entry_name and secret_data and passkey and confirm):
                show_error("All fields are required")
            elif passkey != confirm:
                show_error("Passkeys don't match")
            elif entry_name in stored_data[st.session_state.auth['current_user']]["entries"]:
                show_error("Entry name already exists")
            else:
                encrypted = encrypt_data(secret_data)
                hashed_passkey, salt = hash_passkey(passkey)
                stored_data[st.session_state.auth['current_user']]["entries"][entry_name] = {
                    "data": encrypted,
                    "passkey": hashed_passkey.decode(),
                    "salt": salt.hex()
                }
                save_data(stored_data)
                show_success("Data stored securely!")
                st.code(f"Remember your passkey for '{entry_name}'")

elif choice == "Retrieve Data":
    if not st.session_state.auth['authenticated']:
        show_error("Please login first")
        time.sleep(1)
        st.rerun()
    
    if is_locked_out():
        st.stop()
    
    st.header("Retrieve Your Data")
    
    user_entries = stored_data[st.session_state.auth['current_user']]["entries"]
    if not user_entries:
        st.info("No stored data yet")
        st.stop()
    
    entry_name = st.selectbox("Select entry", list(user_entries.keys()))
    passkey = st.text_input("Enter passkey", type="password")
    
    if st.button("Decrypt"):
        entry_data = user_entries[entry_name]
        try:
            salt = bytes.fromhex(entry_data["salt"])
            hashed_input, _ = hash_passkey(passkey, salt)
            if hashed_input.decode() == entry_data["passkey"]:
                decrypted = decrypt_data(entry_data["data"])
                st.text_area("Decrypted Data", value=decrypted, height=200)
                st.session_state.auth['failed_attempts'] = 0
            else:
                raise ValueError("Invalid passkey")
        except:
            st.session_state.auth['failed_attempts'] += 1
            attempts_left = MAX_ATTEMPTS - st.session_state.auth['failed_attempts']
            show_error(f"Wrong passkey! {attempts_left} attempts left")
            
            if st.session_state.auth['failed_attempts'] >= MAX_ATTEMPTS:
                st.session_state.auth['lockout_time'] = time.time()
                show_error("Too many attempts! Account locked for 5 minutes")