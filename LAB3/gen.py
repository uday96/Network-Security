import os
from Crypto.Cipher import AES
import base64

key = '0123456789abcdef'
IV = 16 * '\x00'           # Initialization vector: discussed later
mode = AES.MODE_CBC

currdir = os.getcwd()
# -------b64 aes128 encrypted Kc for each user--------
for i in range(1,11):
	text = "as"
	if(i<10):
		text += "0"*9+"user"+str(i)
	else:
		text += "0"*8+"user"+str(i)
	print text
	encryptor = AES.new(key, mode, IV=IV)
	ciphertext = encryptor.encrypt(text)
	b64ciphertext = base64.b64encode(ciphertext)
	print b64ciphertext
	file = open(currdir+"/AS/keys_kc_user"+str(i)+".txt",'w')
	file.write(b64ciphertext)
	file.close()

# -------b64 aes128 encrypted Ktgs same for all users--------
text = "tgs"+'0'*5+"allusers"
encryptor = AES.new(key, mode, IV=IV)
ciphertext = encryptor.encrypt(text)
b64ciphertext = base64.b64encode(ciphertext)
print b64ciphertext
file = open(currdir+"/AS/keys_tgs.txt",'w')
file.write(b64ciphertext)
file.close()

# -------b64 encrypted Kc for each user--------
for i in range(1,11):
	text = "as"
	if(i<10):
		text += "0"*9+"user"+str(i)
	else:
		text += "0"*8+"user"+str(i)
	print text
	b64text = base64.b64encode(text)
	print b64text
	file = open(currdir+"/user"+str(i)+"/key",'w')
	file.write(b64text)
	file.close()

# -------b64 encrypted Kv for each file server--------
for i in range(1,10):
	text = "Kv"+"0"*11+"FS"+str(i)
	print text
	b64text = base64.b64encode(text)
	print b64text
	file = open(currdir+"/FS"+str(i)+"/key",'w')
	file.write(b64text)
	file.close()

# -------b64 aes128 encrypted Kv for each file server--------
for i in range(1,10):
	text = "Kv"+"0"*11+"FS"+str(i)
	print text
	encryptor = AES.new(key, mode, IV=IV)
	ciphertext = encryptor.encrypt(text)
	b64ciphertext = base64.b64encode(ciphertext)
	print b64ciphertext
	file = open(currdir+"/TGS/keys_kv_FS"+str(i)+".txt",'w')
	file.write(b64ciphertext)
	file.close()
	
# -------gen user sub dirs in FS dirs-------------------------
for i in range(1,10):
	for u in range(1,11):
		os.system("mkdir "+currdir+"/FS"+str(i)+"/user"+str(u))