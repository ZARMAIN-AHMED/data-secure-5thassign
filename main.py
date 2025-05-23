import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Initialize session state variables
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'reauthorized' not in st.session_state:
    st.session_state.reauthorized = False

# Generate a symmetric key for encryption
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data storage
stored_data = {}  # Format: { "encrypted_text": { "encrypted_text": "...", "passkey": "hashed_passkey" } }

# Hash passkey using SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt user data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt stored data
def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)

    for value in stored_data.values():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed:
            st.session_state.failed_attempts = 0  # Reset failed attempts
            return cipher.decrypt(encrypted_text.encode()).decode()

    # If not found or incorrect
    st.session_state.failed_attempts += 1
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Sidebar menu
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📌 Navigation", menu)

# ------------------ Home Page ------------------
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using a unique passkey.")

# ------------------ Store Data ------------------
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("📝 Enter Data:")
    passkey = st.text_input("🔑 Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data stored securely!")
            st.code(encrypted_text, language='text')
        else:
            st.error("⚠️ Both fields are required!")

# ------------------ Retrieve Data ------------------
elif choice == "Retrieve Data":
    if st.session_state.failed_attempts >= 3 and not st.session_state.reauthorized:
        st.warning("🔒 Too many failed attempts! Please login to reauthorize.")
        st.stop()

    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("🔐 Enter Encrypted Data:")
    passkey = st.text_input("🔑 Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success("✅ Data Decrypted Successfully!")
                st.code(decrypted_text, language='text')
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")

                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.session_state.reauthorized = False
                    st.rerun()  # ✅ Fixed rerun
        else:
            st.error("⚠️ Both fields are required!")

# ------------------ Login Page ------------------
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Replace with secure password logic in real app
            st.session_state.failed_attempts = 0
            st.session_state.reauthorized = True
            st.success("✅ Reauthorized successfully! Now go to 'Retrieve Data'.")
        else:
            st.error("❌ Incorrect master password!")
