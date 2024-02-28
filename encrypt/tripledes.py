from Crypto.Cipher import DES3
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter

modes = {
    "ECB": DES3.MODE_ECB,
    "CBC": DES3.MODE_CBC,
    "CTR": DES3.MODE_CTR,
    "CFB": DES3.MODE_CFB,
    "OFB": DES3.MODE_OFB
}

def encrypt(key, data, mode):
    if mode == "ECB":
        cipher = DES3.new(key, DES3.MODE_ECB)
        encrypted = cipher.encrypt(pad(data, DES3.block_size))
    elif mode == "CBC":
        iv = get_random_bytes(DES3.block_size)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        encrypted = iv + cipher.encrypt(pad(data, DES3.block_size))
    elif mode == "CTR":
        ctr = Counter.new(64)
        cipher = DES3.new(key, DES3.MODE_CTR, counter=ctr)
        encrypted = cipher.encrypt(data)
    elif mode == "CFB":
        iv = get_random_bytes(DES3.block_size)
        cipher = DES3.new(key, DES3.MODE_CFB, iv)
        encrypted = iv + cipher.encrypt(data)
    elif mode == "OFB":
        iv = get_random_bytes(DES3.block_size)
        cipher = DES3.new(key, DES3.MODE_OFB, iv)
        encrypted = iv + cipher.encrypt(data)
    else:
        raise ValueError("Invalid 3DES mode.")
    return encrypted


def encryptwithpassword(password, plaintext, mode, size):
    salt = get_random_bytes(size)  # 生成盐，3DES使用较短的盐值也足够
    key = PBKDF2(password, salt, dkLen=24, count=100000, hmac_hash_module=SHA256)  # 从密码派生24字节(192位)的密钥

    if mode == "ECB":
        cipher = DES3.new(key, DES3.MODE_ECB)
        encrypted = cipher.encrypt(pad(plaintext, DES3.block_size))
    elif mode == "CBC":
        iv = get_random_bytes(DES3.block_size)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        encrypted = iv + cipher.encrypt(pad(plaintext, DES3.block_size))
    elif mode == "CTR":
        ctr = Counter.new(64)
        cipher = DES3.new(key, DES3.MODE_CTR, counter=ctr)
        encrypted = cipher.encrypt(plaintext)
    elif mode == "CFB":
        iv = get_random_bytes(DES3.block_size)
        cipher = DES3.new(key, DES3.MODE_CFB, iv)
        encrypted = iv + cipher.encrypt(plaintext)
    elif mode == "OFB":
        iv = get_random_bytes(DES3.block_size)
        cipher = DES3.new(key, DES3.MODE_OFB, iv)
        encrypted = iv + cipher.encrypt(plaintext)
    else:
        raise ValueError("Invalid 3DES mode.")
    return salt + encrypted

def decrypt(key, encrypted_data, mode):
    if mode == "ECB":
        cipher = DES3.new(key, DES3.MODE_ECB)
        decrypted = unpad(cipher.decrypt(encrypted_data), DES3.block_size)
    elif mode in ("CBC", "CFB", "OFB"):
        iv = encrypted_data[:DES3.block_size]
        encrypted_data = encrypted_data[DES3.block_size:]
        cipher = DES3.new(key, modes[mode], iv)
        decrypted = cipher.decrypt(encrypted_data)
        if mode == "CBC":
            decrypted = unpad(decrypted, DES3.block_size)
    elif mode == "CTR":
        ctr = Counter.new(64)
        cipher = DES3.new(key, DES3.MODE_CTR, counter=ctr)
        decrypted = cipher.decrypt(encrypted_data)
    else:
        raise ValueError("Invalid 3DES mode.")
    return decrypted


def decryptwithpassword(password, encrypted_data, mode, size):
    # 提取盐值和实际加密的数据
    salt = encrypted_data[:size]
    encrypted_data = encrypted_data[size:]

    # 使用相同的参数重新生成密钥
    key = PBKDF2(password, salt, dkLen=24, count=100000, hmac_hash_module=SHA256)

    # 根据不同的模式解密数据
    if mode == "ECB":
        cipher = DES3.new(key, DES3.MODE_ECB)
        decrypted = unpad(cipher.decrypt(encrypted_data), DES3.block_size)
    elif mode in ("CBC", "CFB", "OFB"):
        # 对于这些模式，IV是加密数据的第一部分
        iv = encrypted_data[:DES3.block_size]
        encrypted_data = encrypted_data[DES3.block_size:]
        cipher = DES3.new(key, DES3.MODE_CBC if mode == "CBC" else DES3.MODE_CFB if mode == "CFB" else DES3.MODE_OFB,
                          iv)
        decrypted = cipher.decrypt(encrypted_data)
        if mode == "CBC":
            decrypted = unpad(decrypted, DES3.block_size)
    elif mode == "CTR":
        ctr = Counter.new(64)
        cipher = DES3.new(key, DES3.MODE_CTR, counter=ctr)
        decrypted = cipher.decrypt(encrypted_data)
    else:
        raise ValueError("Invalid 3DES mode.")

    return decrypted

def encrypt_file(file_path, key, mode):
    with open(file_path, "rb") as file:
        data = file.read()

    encrypted_data = encrypt(key, data, mode)

    with open(file_path, "wb") as file:
        file.write(encrypted_data)


def decrypt_file(file_path, key, mode):
    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = decrypt(key, encrypted_data, mode)

    with open(file_path, "wb") as file:
        file.write(decrypted_data)

def encrypt_file_saveas(file_path, key, mode, saveas_path):
    with open(file_path, "rb") as file:
        data = file.read()

    encrypted_data = encrypt(key, data, mode)

    with open(saveas_path, "wb") as file:
        file.write(encrypted_data)


def decrypt_file_saveas(file_path, key, mode, saveas_path):
    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = decrypt(key, encrypted_data, mode)

    with open(saveas_path, "wb") as file:
        file.write(decrypted_data)

def encrypt_file_withpassword(file_path, password, mode, size):
    with open(file_path, "rb") as file:
        data = file.read()

    encrypted_data = encryptwithpassword(password,data,mode,size)

    with open(file_path, "wb") as file:
        file.write(encrypted_data)


def decrypt_file_withpassword(file_path, password, mode, size):
    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = decryptwithpassword(password,encrypted_data,mode,size)

    with open(file_path, "wb") as file:
        file.write(decrypted_data)

def encrypt_file_saveas_withpassword(file_path, password, mode, saveas_path, size):
    with open(file_path, "rb") as file:
        data = file.read()

    encrypted_data = encryptwithpassword(password,data,mode,size)

    with open(saveas_path, "wb") as file:
        file.write(encrypted_data)


def decrypt_file_saveas_withpassword(file_path, password, mode, saveas_path,size):
    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = decryptwithpassword(password,encrypted_data,mode,size)

    with open(saveas_path, "wb") as file:
        file.write(decrypted_data)
# # Example usage
# data = b"Secret message"
# key = DES3.adjust_key_parity(get_random_bytes(24))
#
# # Encrypt and decrypt with each mode
# for mode in ["ECB","CBC","CTR","CFB","OFB"]:
#     encrypted = encrypt(key,data, mode)
#     decrypted = decrypt(key,encrypted, mode)
#     print(f"Mode: {mode}, Decrypted: {decrypted.decode()}")
