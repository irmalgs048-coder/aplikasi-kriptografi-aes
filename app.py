import streamlit as st
import base64, hashlib
from cryptography.fernet import Fernet

# ===================== CRYPTO =====================
def make_key(password):
    return base64.urlsafe_b64encode(
        hashlib.sha256(password.encode()).digest()
    )

# ===================== PAGE CONFIG =====================
st.set_page_config(
    page_title="AES Crypto App",
    page_icon="🔐",
    layout="centered"
)

st.title("🔐 AES Encryption Tool (Streamlit)")
st.caption("Enkripsi & Dekripsi teks menggunakan password")

# ===================== SESSION STATE =====================
if "encrypted" not in st.session_state:
    st.session_state.encrypted = ""

if "decrypted" not in st.session_state:
    st.session_state.decrypted = ""

if "text" not in st.session_state:
    st.session_state.text = ""

if "password" not in st.session_state:
    st.session_state.password = ""

# ===================== INPUT =====================
st.session_state.text = st.text_area(
    "📝 Input Teks / Ciphertext",
    value=st.session_state.text,
    height=120
)

st.session_state.password = st.text_input(
    "🔑 Password",
    value=st.session_state.password,
    type="password"
)

col1, col2 = st.columns(2)

# ===================== BUTTONS =====================
with col1:
    if st.button("🔒 ENKRIPSI"):
        if st.session_state.text == "" or st.session_state.password == "":
            st.warning("⚠️ Teks atau password kosong")
        else:
            f = Fernet(make_key(st.session_state.password))
            st.session_state.encrypted = f.encrypt(
                st.session_state.text.encode()
            ).decode()
            st.session_state.decrypted = ""
            st.success("✅ Enkripsi berhasil")

with col2:
    if st.button("🔓 DEKRIPSI"):
        if st.session_state.encrypted == "" or st.session_state.password == "":
            st.warning("⚠️ Ciphertext atau password kosong")
        else:
            try:
                f = Fernet(make_key(st.session_state.password))
                st.session_state.decrypted = f.decrypt(
                    st.session_state.encrypted.encode()
                ).decode()
                st.success("✅ Dekripsi berhasil")
            except:
                st.error("❌ Password salah atau data tidak valid")

# ===================== OUTPUT =====================
st.text_area(
    "📦 Hasil Enkripsi",
    value=st.session_state.encrypted,
    height=120
)

st.text_area(
    "📤 Hasil Dekripsi",
    value=st.session_state.decrypted,
    height=120
)

# ===================== CLEAR =====================
if st.button("🧹 CLEAR"):
    st.session_state.text = ""
    st.session_state.password = ""
    st.session_state.encrypted = ""
    st.session_state.decrypted = ""
    st.rerun()

st.markdown("---")
st.caption("🚀 Python • Cryptography • Streamlit")
