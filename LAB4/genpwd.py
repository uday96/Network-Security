import random, string, base64, hashlib
from Crypto.Cipher import AES

def randomword(length):
	letters = string.ascii_lowercase+string.ascii_uppercase+string.digits
	return ''.join(random.choice(letters) for i in range(length))

def AES_Encrypt(KEY,IV,data):
	data = chr(0)+data
	paddint = 0
	while(len(data)%16!=0):
		data+='\x00'
		paddint+=1
	data = chr(paddint) + data[1:]
	mode = AES.MODE_CBC
	encryptor = AES.new(KEY, mode, IV=IV)
	ciphertext = encryptor.encrypt(data)
	b64ciphertext = base64.b64encode(ciphertext)
	return b64ciphertext

passphrase = raw_input("passphrase : ")

salt = randomword(8)

pwdhash = hashlib.sha256(passphrase).hexdigest()

AES_128_KEY = pwdhash[:16]
AES_128_IV = pwdhash[16:32]

plaintext = '0'*16

salt = salt + '0'*8

pwdenc = AES_Encrypt(AES_128_KEY,AES_128_IV,plaintext)

password = salt + pwdenc

print password