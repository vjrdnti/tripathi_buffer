import numpy as np
from PIL import Image
import numpy.testing as npt
from t_buffer.tripathi_buffer import TripathiBuffer

def main():
    # Generate random images
    h, w = 64, 64
    orig_arr = np.random.randint(0, 256, size=(h, w, 3), dtype=np.uint8)
    key_arr  = np.random.randint(0, 256, size=(h, w, 3), dtype=np.uint8)
    user_key = "testpassword"

    # 1) Noise-based encryption/decryption
    enc_arr, tkey_noise = TripathiBuffer.encrypt(orig_arr, user_key)
    dec_arr = TripathiBuffer.decrypt(enc_arr, tkey_noise, user_key)
    npt.assert_array_equal(dec_arr, orig_arr)
    print("✅ Noise-based encryption/decryption passed")

    # 2) Image-based encryption/decryption
    orig_img = Image.fromarray(orig_arr)
    key_img  = Image.fromarray(key_arr)
    tkey_img = TripathiBuffer.encrypt_from_image(orig_img, key_img, user_key)
    dec2_arr = TripathiBuffer.decrypt_from_image(tkey_img, user_key, key_img)
    npt.assert_array_equal(dec2_arr, orig_arr)
    print("✅ Image-based encryption/decryption passed")

if __name__ == "__main__":
    main()
