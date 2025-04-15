import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import json, os
import time

DATA_FILE = "data.json"
USER_FILE = "user.json"
KEY_FILE = "secret.key"

# ---------------------------
# Load/Create Encryption Key
# ---------------------------
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as file:
            return file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as file:
            file.write(key)
        return key

Key = load_or_create_key()
Cipher = Fernet(Key)

# ---------------------------
# Load/Save User Data
# ---------------------------
def users_data():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as file:
            return json.load(file)
    return {}

def save_user(users):
    with open(USER_FILE, "w") as file:
        json.dump(users, file, indent=4)

# ---------------------------
# Load/Save Encrypted Data
# ---------------------------
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    else:
        return {}

def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file, indent=4)

# ---------------------------
# Hashing and Encryption
# ---------------------------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return Cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    # Initialize session state
    if "failed_attempt" not in st.session_state:
        st.session_state.failed_attempt = 0
    if "block_time" not in st.session_state:
        st.session_state.block_time = None

    # Check if currently blocked
    if st.session_state.block_time:
        elapsed = time.time() - st.session_state.block_time
        if elapsed < 60:
            remaining = int(60 - elapsed)
            st.error(f"⏳ Too many failed attempts. Try again in {remaining} seconds.")
            return None
        else:
            st.session_state.block_time = None
            st.session_state.failed_attempt = 0  # Reset after block expires

    my_hash_passkey = hash_passkey(passkey)

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == my_hash_passkey:
            st.session_state.failed_attempt = 0
            return Cipher.decrypt(encrypted_text.encode()).decode()

    # If incorrect
    st.session_state.failed_attempt += 1
    if st.session_state.failed_attempt >= 3:
        st.session_state.block_time = time.time()
        st.error("❌ Too many failed attempts. You are blocked for 60 seconds.")
    else:
        attempts_left = 3 - st.session_state.failed_attempt
        st.error(f"Wrong passkey! Attempts left: {attempts_left}")
    return None

# ---------------------------
# App UI
# ---------------------------
st.set_page_config(page_title="🔐 Secure Data Vault", layout="centered")

stored_data = load_data()
users = users_data()

if "user" not in st.session_state:
    st.session_state.user = None

# ---------------------------
# Login/Register Screen
# ---------------------------
if not st.session_state.user:
    st.title("🔐 Secure Data Vault")
    st.caption("A secure place to encrypt and store your sensitive notes or information.")
    tab1, tab2 = st.tabs(["🔑 Login", "🆕 Register"])

    with tab1:
        st.subheader("🔑 Login")
        login_username = st.text_input("Username")
        login_password = st.text_input("Password", type="password")

        if st.button("Login"):
            if login_username in users and users[login_username] == hash_passkey(login_password):
                st.session_state.user = login_username
                st.success("✅ Logged in successfully!")
                st.rerun()
            else:
                st.error("❌ Incorrect credentials")

    with tab2:
        st.subheader("🆕 Register")
        new_username = st.text_input("New Username")
        new_password = st.text_input("New Password", type="password")

        if st.button("Register"):
            if new_username in users:
                st.warning("⚠️ Username already exists")
            elif new_username and new_password:
                users[new_username] = hash_passkey(new_password)
                save_user(users)
                st.success("✅ User registered successfully")
            else:
                st.error("Please fill in all fields")

# ---------------------------
# Main App Navigation
# ---------------------------
else:
    st.sidebar.title(f"👋 Welcome, {st.session_state.user}")
    st.markdown(
        """
        <style>
        div[data-testid="stSidebar"] div[role="radiogroup"] > label {
            background: #f0f2f6;
            padding: 10px 20px;
            margin: 5px 0;
            border-radius: 8px;
            display: block;
            cursor: pointer;
            transition: 0.2s all;
        }
        div[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {
            background: #d0e0fc;
        }
        div[data-testid="stSidebar"] div[role="radiogroup"] > label[data-selected="true"] {
            background: #1f77ff !important;
            color: white !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    choice = st.sidebar.radio("Navigation", ["🏠 Home", "📦 Store Data", "🔓 Retrieve Data", "🚪 Logout"])

    if choice == "🏠 Home":
        st.title("🏠 Welcome to Secure Data Vault")
        st.markdown("""
        This application allows you to:
        - 🔒 **Securely encrypt and store** your personal notes or data
        - 🔐 **Access encrypted data** only with the correct passkey
        - 👥 **Create a user account** to manage your own data

        This is useful for:
        - Storing passwords
        - Saving private notes
        - Keeping confidential messages safe

        🔁 Use the sidebar to navigate between pages.
        """)

    elif choice == "📦 Store Data":
        st.title("📦 Store & Encrypt Data")
        user_data = st.text_area("Enter Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Encrypt & Store"):
            if user_data and passkey:
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data, passkey)

                stored_data[encrypted_text] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey,
                    "user": st.session_state.user
                }
                save_data(stored_data)
                st.success("✅ Data encrypted and stored!")
            else:
                st.error("❗ Please enter both fields")

        st.subheader("🕘 Your Data History")
        for key, val in stored_data.items():
            if val["user"] == st.session_state.user:
                st.code(key)

    elif choice == "🔓 Retrieve Data":
        st.title("🔓 Retrieve & Decrypt Data")
        encrypted_text = st.text_area("Paste Encrypted Data")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                decrypted = decrypt_data(encrypted_text, passkey)
                if decrypted:
                    st.success(f"🔓 Decrypted: {decrypted}")
            else:
                st.error("❗ Both fields required")

    elif choice == "🚪 Logout":
        st.session_state.user = None
        st.success("👋 Logged out successfully")
        st.rerun()
