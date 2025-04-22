import hashlib
import random
import numpy as np
from numpy.random import default_rng
from PIL import Image

class TripathiBuffer:
    @staticmethod
    def get_seed_from_string(s: str) -> int:
        h = hashlib.sha256(s.encode()).hexdigest()
        return int(h, 16) % (2**32)

    @staticmethod
    def generate_noise_from_seed(seed: int, shape: tuple):
        rng = default_rng(seed)
        return rng.integers(0, 256, size=shape, dtype=np.uint8)

    @staticmethod
    def sha256_hash_image(arr: np.ndarray, user_string: str) -> str:
        image_bytes = arr.tobytes()
        return hashlib.sha256(image_bytes + user_string.encode()).hexdigest()

    @staticmethod
    def pick_random_pixels(img: np.ndarray, num_pixels=4):
        h, w, _ = img.shape
        pixels = []
        for _ in range(num_pixels):
            x, y = random.randrange(w), random.randrange(h)
            pixels.append((x, y, tuple(img[y, x])))
        return pixels

    @classmethod
    def encrypt(cls, arr: np.ndarray, user_string: str) -> tuple[np.ndarray, dict]:
        shape = arr.shape
        composite = f"{user_string}_F_P{shape[0]}x{shape[1]}x{shape[2]}"
        seed = cls.get_seed_from_string(composite)
        composite = f"{shape[0]}x{shape[1]}x{shape[2]}"
        noise = cls.generate_noise_from_seed(seed, shape)
        noisy = (arr.astype(int) + noise.astype(int)) % 256
        pixels = cls.pick_random_pixels(noisy)
        composite += "_E_E" + "".join(
            f"_|{x}|{y}|{r}|{g}|{b}" for x, y, (r, g, b) in pixels
        )
        hsh = cls.sha256_hash_image(noisy.astype(np.uint8), user_string)
        composite += f"_HASH_{hsh}"
        tkey = {"method": "noise", "meta": composite}
        return noisy.astype(np.uint8), tkey

    @classmethod
    def decrypt(cls, arr: np.ndarray, tkey: dict, user_string: str) -> np.ndarray:
        composite = tkey["meta"]
        expected_hash = composite.split("_HASH_")[1]
        actual_hash = cls.sha256_hash_image(arr.astype(np.uint8), user_string)
        if expected_hash != actual_hash:
            raise ValueError("Integrity check failed.")
        shape_part = composite.split("_E_E")[0]
        if shape_part != f"{arr.shape[0]}x{arr.shape[1]}x{arr.shape[2]}":
            raise ValueError("Shape mismatch.")
        seed = cls.get_seed_from_string(f"{user_string}_F_P{shape_part}")
        noise = cls.generate_noise_from_seed(seed, arr.shape)
        recovered = (arr.astype(int) - noise.astype(int)) % 256
        return recovered.astype(np.uint8)

    @staticmethod
    def xor_obfuscate(arr: np.ndarray, key: str) -> bytes:
        key_bytes = key.encode()
        if len(key_bytes) == 0:
            raise ValueError("XOR key must be non-empty to avoid modulo by zero.")
        flat = arr.flatten()
        obfuscated = bytes(
            [b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(flat)]
        )
        return obfuscated

    @staticmethod
    def xor_deobfuscate(data: bytes, shape: tuple, key: str) -> np.ndarray:
        key_bytes = key.encode()
        if len(key_bytes) == 0:
            raise ValueError("XOR key must be non-empty to avoid modulo by zero.")
        flat = bytes(
            [b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)]
        )
        return np.frombuffer(flat, dtype=np.uint8).reshape(shape)

    @classmethod
    def encrypt_from_image(cls, img: Image.Image, keyimg: Image.Image, user_key: str) -> dict:
        # Resize both images to minimal common dimensions
        min_w = min(img.width, keyimg.width)
        min_h = min(img.height, keyimg.height)
        img_r = img.resize((min_w, min_h), Image.ANTIALIAS)
        key_r = keyimg.resize((min_w, min_h), Image.ANTIALIAS)

        img_arr = np.array(img_r.convert("RGB"), dtype=np.uint8)
        key_arr = np.array(key_r.convert("RGB"), dtype=np.uint8)

        diff = (key_arr.astype(int) - img_arr.astype(int)) % 256
        diff_u8 = diff.astype(np.uint8)
        obf = cls.xor_obfuscate(diff_u8, user_key)

        tkey = {"method": "from_image", "obf_data": obf, "shape": diff_u8.shape}
        return tkey

    @classmethod
    def decrypt_from_image(cls, tkey: dict, user_key: str, keyimg: Image.Image) -> np.ndarray:
        shape = tkey["shape"]
        expected_h, expected_w, _ = shape
        key_r = keyimg.resize((expected_w, expected_h), Image.ANTIALIAS)

        key_arr = np.array(key_r.convert("RGB"), dtype=np.uint8)
        diff = cls.xor_deobfuscate(tkey["obf_data"], shape, user_key).astype(int)
        rec = (key_arr.astype(int) - diff) % 256
        return rec.astype(np.uint8)
