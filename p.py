import io
from crypto_module import * 
from dns_utils import *
from Crypto.Random import get_random_bytes
from utils import *

encryptor = GCMEncryptor()
decryptor = GCMDecryptor()

text = "hello world"
enc = encryptor.encrypt(text)
dec = decryptor(enc)

query =  encode_base32_dns_query(domain_suffix=DOMAIN,id_str="0",base32_string=enc) 
print(query) 




