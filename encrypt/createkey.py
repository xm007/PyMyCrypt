from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, SHA1, MD5
from Crypto.Signature import pkcs1_15, DSS


def generate_key(size=16):
    key = get_random_bytes(size)
    return key
def generate_key_from_password(password, salt,size=16):
    key = PBKDF2(password, salt, dkLen=size, count=1000000, hmac_hash_module=SHA512)
    return key

def generate_rsa():
    key = RSA.generate(2048)
    public_key = key.publickey().exportKey(format='PEM')
    private_key = key.exportKey(format='PEM')
    return public_key, private_key

def generate_ecc():
    key = ECC.generate(curve='P-256')
    private_key = key.export_key(format='PEM')
    public_key = key.public_key().export_key(format='PEM')
    return public_key,private_key,

def sign_file(file_path, private_key_path, saveas_path, hash_algorithm='SHA256' , algorithm='RSA'):
    # 读取文件内容
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # 根据指定的哈希算法创建哈希对象
    if hash_algorithm == 'MD5':
        hasher = MD5.new(file_data)
    elif hash_algorithm == 'SHA1':
        hasher = SHA1.new(file_data)
    else:  # 默认使用SHA256
        hasher = SHA256.new(file_data)

    if algorithm == 'RSA':
        # 读取私钥
        with open(private_key_path, 'r') as f:
            private_key = RSA.import_key(f.read())
        # 签名
        signature = pkcs1_15.new(private_key).sign(hasher)
    else:
        # 读取私钥
        with open(private_key_path, 'r') as f:
            private_key = ECC.import_key(f.read())
        # 签名
        signer = DSS.new(private_key, 'fips-186-3')
        signature = signer.sign(hasher)
    with open(saveas_path, 'wb') as signfile:
        signfile.write(signature)

def verify_signature(file_path, signature_path, public_key_path, hash_algorithm='SHA256',algorithm='RSA'):
    # 读取文件内容
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # 根据指定的哈希算法创建哈希对象
    if hash_algorithm == 'MD5':
        hasher = MD5.new(file_data)
    elif hash_algorithm == 'SHA1':
        hasher = SHA1.new(file_data)
    else:  # 默认使用SHA256
        hasher = SHA256.new(file_data)

    # 读取签名
    with open(signature_path, 'rb') as s:
        signature = s.read()

    if algorithm == 'RSA':
        # 读取公钥
        with open(public_key_path, 'r') as f:
            public_key = RSA.import_key(f.read())

        try:
            # 使用公钥验证签名
            pkcs1_15.new(public_key).verify(hasher, signature)
            return True  # 签名验证成功
        except (ValueError, TypeError):
            return False  # 签名验证失败
    else:
        # 读取公钥
        with open(public_key_path, 'r') as f:
            public_key = ECC.import_key(f.read())

        # 创建一个验证者对象并验证
        verifier = DSS.new(public_key, 'fips-186-3')
        try:
            verifier.verify(hasher, signature)
            return True  # 签名验证成功
        except ValueError:
            return False  # 签名验证失败


def secure_key_with_rsa(public_key,key):
    # 使用 RSA 公钥加密 AES 密钥
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(key)
    return encrypted_key

def decrypt_key_with_rsa(private_key,encrypted_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_key = cipher_rsa.decrypt(encrypted_key)
    return decrypted_key


