from pgpy import PGPKey, PGPMessage, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm


# ===================================
# 创建密钥
# ===================================
def pgp_createkeypair(name: str,keyprotect: []=[""]):

    # 创建一个新的密钥对
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)

    # 创建一个新的身份证
    uid = PGPUID.new(f'{name}', email=f'{name}@pymycrypt.com')

    # 使用身份证创建PGP密钥
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA512],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression= \
                    [CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2,
                     CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
    if keyprotect[0] == True:
        key.protect(f"{keyprotect[1]}", SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

    with open(f"{name}_private_key.asc", "wb") as file_out:
        file_out.write(bytes(key))

    with open(f"{name}_public_key.asc", "wb") as file_out:
        file_out.write(bytes(key.pubkey))