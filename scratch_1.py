# ========================================
# 生成RSA私钥和公钥
# ========================================

from Crypto.PublicKey import RSA

key = RSA.generate(2048)
private_key = key.exportKey()
with open("./private.pem", "wb") as f:
    f.write(private_key)

public_key = key.publickey().exportKey()
with open("receiver.pem", "wb") as f:
    f.write(public_key)

# ========================================
# 加密文件
# ========================================
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

with open("testfile.txt", "rb") as data:
    with open("encrypted_data.bin", "wb") as f:
        recipient_key = RSA.import_key(open("./receiver.pem").read())
        session_key = get_random_bytes(32)

        # 使用RSA公钥加密初始密钥
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # 使用AES加密信息
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data.read())
        [f.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]

# ========================================
# decrypt
# ========================================
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

with open("encrypted_data.bin", "rb") as f:
    private_key = RSA.import_key(open("private.pem").read())

    enc_session_key, nonce, tag, ciphertext = \
        [f.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

    # 使用私钥解密初始密钥
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # 使用初始密钥解密信息
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print(data.decode("utf-8"))
