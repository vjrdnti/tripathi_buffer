import streamlit as st
from PIL import Image
import numpy as np
from io import BytesIO
import pickle
import json
from t_buffer.tripathi_buffer import TripathiBuffer

st.set_page_config(page_title="TripathiBuffer", page_icon="🔒", layout="wide")
st.markdown("<h1 style='text-align:center;'>🔐 TripathiBuffer</h1>", unsafe_allow_html=True)

def np_to_png_bytes(arr: np.ndarray) -> bytes:
    img = Image.fromarray(arr.astype(np.uint8))
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

tab1, tab2 = st.tabs(["Encrypt", "Decrypt"])

with tab1:
    st.subheader("Encrypt")
    method = st.selectbox("Method", ["Noise-based", "Image-based"])
    img_file = st.file_uploader("Upload image (PNG)", type=["png"], key="enc_img")
    if method == "Image-based":
        key_file = st.file_uploader("Upload key image (PNG)", type=["png"], key="enc_key")
    password = st.text_input("Password / Key", type="password", key="enc_pass")

    if st.button("🔐 Encrypt"):
        if not img_file or not password or (method == "Image-based" and not key_file):
            st.warning("Please provide all required inputs.")
        else:
            img = Image.open(img_file).convert("RGB")
            if method == "Noise-based":
                arr = np.array(img, dtype=np.uint8)
                enc_arr, tkey = TripathiBuffer.encrypt(arr, password)
                st.image(enc_arr, caption="Encrypted Image", use_container_width=True)
                st.download_button("⬇ Download Encrypted PNG", np_to_png_bytes(enc_arr), "encrypted.png")
                tkey_json = json.dumps(tkey)
                st.download_button("⬇ Download tkey (JSON)", tkey_json, "tkey_noise.json")
            else:
                key_img = Image.open(key_file).convert("RGB")
                tkey = TripathiBuffer.encrypt_from_image(img, key_img, password)
                st.success("Generated tkey for image-based encryption.")
                tkey_bytes = pickle.dumps(tkey)
                st.download_button("⬇ Download tkey (PKL)", tkey_bytes, "tkey_from_image.pkl")

with tab2:
    st.subheader("Decrypt")
    method = st.selectbox("Method", ["Noise-based", "Image-based"], key="dec_method")
    
    if method == "Noise-based":
        enc_file = st.file_uploader("Upload encrypted image (PNG)", type=["png"], key="dec_img")
        tkey_file = st.file_uploader("Upload tkey (JSON)", type=["json"], key="dec_tkey_noise")
    else:
        key_file = st.file_uploader("Upload key image (PNG)", type=["png"], key="dec_key")
        tkey_file = st.file_uploader("Upload tkey (PKL)", type=["pkl"], key="dec_tkey_img")

    password = st.text_input("Password / Key", type="password", key="dec_pass")

    if st.button("🔓 Decrypt"):
        if not password or not tkey_file or (method=="Image-based" and not key_file) or (method=='Noise-based' and not enc_file):
            st.warning("Please provide all required inputs.")
        else:
            if method == "Noise-based":
                enc_img = Image.open(enc_file).convert("RGB")
                tkey = json.load(tkey_file)
                dec_arr = TripathiBuffer.decrypt(np.array(enc_img), tkey, password)
            else:
                key_img = Image.open(key_file).convert("RGB")
                tkey = pickle.load(tkey_file)
                dec_arr = TripathiBuffer.decrypt_from_image(tkey, password, key_img)

            st.image(dec_arr, caption="Decrypted Image", use_container_width=True)
            st.download_button("⬇ Download Decrypted PNG", np_to_png_bytes(dec_arr), "decrypted.png")
