from pgpy import PGPKey, PGPMessage, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

#===================================
# 创建密钥
#===================================
# 创建一个新的密钥对
key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)

# 创建一个新的身份证
uid = PGPUID.new('xm007', email='xm007@pymycrypt.com')

# 使用身份证创建PGP密钥
key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA512],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression= \
                [CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2,
                 CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
key.protect("123456",SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

with open("xm007_private_key.asc", "wb") as file_out:
    file_out.write(bytes(key))

with open("xm007_public_key.asc", "wb") as file_out:
    file_out.write(bytes(key.pubkey))

#=====================================
# 加密文件
#=====================================

message = PGPMessage.new("testfile.txt", file=True)
public_key,_ = PGPKey.from_file("xm007_public_key.asc")
enc_message = public_key.encrypt(message)
with open("testfile.txt.pmc", "wb") as file_out:
    file_out.write(bytes(enc_message))

#=====================================
# 解密文件
#=====================================

message_file_in = PGPMessage.from_file("testfile.txt.pmc")
private_key,_ = PGPKey.from_file("xm007_private_key.asc")
with private_key.unlock("123456"):
    dec_file = private_key.decrypt(message_file_in).message
    print(dec_file.decode("utf-8"))
    # with open("xm007_enc_testfil_new.txt","wb") as file_out:
    #     file_out.write(dec_pgpmessage_file_in.message)


