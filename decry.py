from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import time

pub_key = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAMZ25lt7KbsuXJtiRqFYJeRoRf6BWZonlHYonIlOUQ/d58QL9gC/qzmH
IVkl6bNIMFp//Xjnfb4Sv6Lr7Rxab0PUNMND3N4fGcXOtBif2asS1aXWJ+UX8ofA
8eGrMNX9sCbGRFCYam+g6fYR8kmu8b0xhqnca7DMUrjCuv3JswHtAgMBAAE=
-----END RSA PUBLIC KEY-----"""




pub = RSA.importKey(pub_key)
cipher = PKCS1_v1_5.new(pub)
ts = str(time.time())[0:10]
content = "time="+ts+"&sign=megvii"
encrypt_hex = cipher.encrypt(content.encode(encoding='utf-8')).hex()
args = "time="+ts+"&signature="+encrypt_hex
print(args)
