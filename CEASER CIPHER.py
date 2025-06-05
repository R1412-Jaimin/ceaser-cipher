import struct

DELTA = 0x9E3779B9
NUM_ROUNDS = 32
BLOCK_SIZE = 8  # bytes per block (64 bits)
KEY_SIZE = 16   # bytes per key (128 bits)

def derive_key(shift: int) -> bytes:
    """
    Derive a 128-bit (16 bytes) key from the integer shift value.
    We'll repeat the shift in different rotated ways to fill 16 bytes.
    """
    shift = shift & 0xffffffff
    parts = [
        shift,
        ((shift << 5) | (shift >> 27)) & 0xffffffff,
        ((shift << 13) | (shift >> 19)) & 0xffffffff,
        ((shift << 21) | (shift >> 11)) & 0xffffffff
    ]
    return struct.pack('>4I', *parts)

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """
    Pad data to a multiple of block_size using PKCS7 padding.
    """
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS7 padding.
    """
    if not data:
        return data
    padding_len = data[-1]
    if padding_len < 1 or padding_len > BLOCK_SIZE:
        raise ValueError("Invalid padding length.")
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding bytes.")
    return data[:-padding_len]

def tea_encrypt_block(v0: int, v1: int, key: bytes) -> (int, int):
    """
    Encrypt a single 64-bit block (v0, v1) using TEA and 128-bit key.
    v0, v1: unsigned 32-bit ints
    key: 16 bytes
    Returns encrypted tuple (v0, v1).
    """
    k = struct.unpack('>4I', key)
    sum_ = 0
    for _ in range(NUM_ROUNDS):
        sum_ = (sum_ + DELTA) & 0xffffffff
        v0 = (v0 + (((v1 << 4) + k[0]) ^ (v1 + sum_) ^ ((v1 >> 5) + k[1]))) & 0xffffffff
        v1 = (v1 + (((v0 << 4) + k[2]) ^ (v0 + sum_) ^ ((v0 >> 5) + k[3]))) & 0xffffffff
    return v0, v1

def tea_decrypt_block(v0: int, v1: int, key: bytes) -> (int, int):
    """
    Decrypt a single 64-bit block (v0, v1) using TEA and 128-bit key.
    Returns decrypted tuple (v0, v1).
    """
    k = struct.unpack('>4I', key)
    sum_ = (DELTA * NUM_ROUNDS) & 0xffffffff
    for _ in range(NUM_ROUNDS):
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + sum_) ^ ((v0 >> 5) + k[3]))) & 0xffffffff
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + sum_) ^ ((v1 >> 5) + k[1]))) & 0xffffffff
        sum_ = (sum_ - DELTA) & 0xffffffff
    return v0, v1

def encrypt(plaintext: str, shift: int) -> str:
    """
    Encrypts the plaintext with TEA cipher using key derived from shift.
    Returns hex string of encrypted data.
    """
    key = derive_key(shift)
    data = plaintext.encode('utf-8')
    padded = pkcs7_pad(data, BLOCK_SIZE)

    encrypted_blocks = []
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i+BLOCK_SIZE]
        v0, v1 = struct.unpack('>2I', block)
        enc0, enc1 = tea_encrypt_block(v0, v1, key)
        encrypted_blocks.append(struct.pack('>2I', enc0, enc1))
    encrypted_bytes = b''.join(encrypted_blocks)
    return encrypted_bytes.hex()

def decrypt(cipher_hex: str, shift: int) -> str:
    """
    Decrypts the hex cipher text with TEA cipher using key derived from shift.
    Returns the decrypted plaintext string.
    """
    key = derive_key(shift)
    cipher_bytes = bytes.fromhex(cipher_hex)
    if len(cipher_bytes) % BLOCK_SIZE != 0:
        raise ValueError("Invalid ciphertext length: not multiple of block size.")

    decrypted_blocks = []
    for i in range(0, len(cipher_bytes), BLOCK_SIZE):
        block = cipher_bytes[i:i+BLOCK_SIZE]
        v0, v1 = struct.unpack('>2I', block)
        dec0, dec1 = tea_decrypt_block(v0, v1, key)
        decrypted_blocks.append(struct.pack('>2I', dec0, dec1))
    decrypted_bytes = b''.join(decrypted_blocks)
    unpadded = pkcs7_unpad(decrypted_bytes)
    return unpadded.decode('utf-8')

def main():
    print("=== TEA Cipher Encryption/Decryption ===")
    while True:
        print("\nChoose an option:")
        print("1) Encrypt")
        print("2) Decrypt")
        print("3) Exit")
        choice = input("Your choice: ").strip()
        if choice == '1':
            plaintext = input("Enter message to encrypt: ")
            shift_str = input("Enter shift value (integer 0 to 4294967295): ")
            try:
                shift = int(shift_str)
                if shift < 0 or shift > 0xFFFFFFFF:
                    raise ValueError
            except ValueError:
                print("Invalid shift value. Must be integer between 0 and 4294967295.")
                continue
            encrypted = encrypt(plaintext, shift)
            print("\nEncrypted (hex):")
            print(encrypted)

        elif choice == '2':
            cipher_hex = input("Enter hex ciphertext to decrypt: ").strip()
            shift_str = input("Enter shift value (integer 0 to 4294967295): ")
            try:
                shift = int(shift_str)
                if shift < 0 or shift > 0xFFFFFFFF:
                    raise ValueError
            except ValueError:
                print("Invalid shift value. Must be integer between 0 and 4294967295.")
                continue
            try:
                decrypted = decrypt(cipher_hex, shift)
                print("\nDecrypted message:")
                print(decrypted)
            except Exception as e:
                print(f"Decryption failed: {e}")
        elif choice == '3':
            print("Exiting. Goodbye!")
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()

