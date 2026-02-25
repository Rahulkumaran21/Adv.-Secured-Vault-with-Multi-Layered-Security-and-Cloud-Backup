from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# 1. Key Generation (Simulates Login)
def generate_key(password: str, salt: bytes = None) -> (bytes, bytes):
    if not salt:
        salt = get_random_bytes(16)
    # Derive a 32-byte (256-bit) key from the password
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    return key, salt

# 2. Encryption (The "Lock")
def encrypt_data(data: bytes, key: bytes) -> (bytes, bytes, bytes):
    iv = get_random_bytes(16)
    # GCM Mode is preferred for modern security (provides integrity + confidentiality)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, tag, iv

# 3. Decryption (The "Unlock") - ADD THIS
def decrypt_data(ciphertext: bytes, tag: bytes, iv: bytes, key: bytes) -> bytes:
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        # decrypt_and_verify ensures the data wasn't tampered with
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        return None # Decryption failed (wrong key or corrupted data)

# 4. Test Block
if __name__ == "__main__":
    print("--- 🔒 STARTING SECURITY TEST ---")
    
    # Simulate User Input
    password = "super_secure_password"
    original_text = b"This is my secret project data."
    print(f"📄 Original Data: {original_text}")

    # Step A: Generate Key
    key, salt = generate_key(password)
    print(f"🔑 Derived Key: {key.hex()[:10]}... (hidden)")

    # Step B: Encrypt
    encrypted, tag, iv = encrypt_data(original_text, key)
    print(f"🔒 Encrypted content: {encrypted.hex()[:20]}...")

    # Step C: Decrypt (The Moment of Truth)
    decrypted_text = decrypt_data(encrypted, tag, iv, key)
    
    if decrypted_text == original_text:
        print(f"✅ SUCCESS: Decrypted data matches! -> {decrypted_text}")
    else:
        print("❌ FAILED: Data mismatch or decryption error.")

    # Step D: Test Tampering (Hacker Simulation)
    print("\n--- 🕵️ TAMPERING TEST ---")
    fake_tag = get_random_bytes(16) # Attacker tries to fake the integrity tag
    result = decrypt_data(encrypted, fake_tag, iv, key)
    if result is None:
        print("✅ SUCCESS: System detected tampering and refused to decrypt.")
    else:
        print("❌ FAILED: System accepted corrupted data.")
