import os, sys, socket, base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import ast, json, hashlib

def generate_RSA(bits=2048):
    '''
    Generate an RSA keypair in PEM format
    param: bits The key length in bits
    Return private key and public key
    '''
    from Crypto.PublicKey import RSA 
    new_key = RSA.generate(bits) 
    public_key = new_key.publickey().exportKey("PEM") 
    private_key = new_key.exportKey("PEM") 
    keyFile = open('serverpub.txt','w')
    keyFile.write(public_key)
    keyFile.close()
    keyFile = open('serverpriv.txt','w')
    keyFile.write(private_key)
    keyFile.close()

def AES_Encrypt(data,key,IV=(16 * '\x00')):
	data = chr(0)+data
	paddint = 0
	while(len(data)%16!=0):
		data+='\x00'
		paddint+=1
	data = chr(paddint) + data[1:]
	mode = AES.MODE_CBC
	encryptor = AES.new(key, mode, IV=IV)
	cipherticket = encryptor.encrypt(data)
	b64cipherticket = base64.b64encode(cipherticket)
	return b64cipherticket

def AES_Decrypt(data,key):
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	decryptor = AES.new(key, mode, IV=IV)
	cipherticket = base64.b64decode(data)
	plaintext = decryptor.decrypt(cipherticket)
	paddint = ord(plaintext[0])
	plaintext = plaintext[1:-1*paddint]
	return plaintext

def get_RSA_key(type):
	fname = 'serverpriv.txt'
	if(type == 'public'):
		fname = 'serverpub.txt'
	keyFile = open(fname,'r')
	key = keyFile.read()
	keyFile.close()
	return key

def gen_pwd(passphrase):
	pwdhash = hashlib.sha256(passphrase).hexdigest()
	AES_128_KEY = pwdhash[:16]
	AES_128_IV = pwdhash[16:32]
	plaintext = '0'*16
	pwdenc = AES_Encrypt(plaintext,AES_128_KEY,AES_128_IV)
	print pwdenc
	return pwdenc

def auth(auth_payload):
	CURR_DIR = os.getcwd()
	try:
		userFile = open(CURR_DIR+'/UserCredentials/'+auth_payload['username']+'.txt','r')
	except Exception as e:
		print "Error: "+str(e)
		return 'NOK', None
	username = userFile.readline()
	if(username[-1] == '\n'):
		username = username[:-1]
	if(username != auth_payload['username']):
		print "username mismatch : ", username, auth_payload['username']
		return 'NOK', None
	password = userFile.readline()
	if(password[-1] == '\n'):
		password = password[1:-1]
	print password
	if(password[16:] != gen_pwd(auth_payload['passphrase'])):
		print "password mismatch : ", auth_payload['passphrase']
		return 'NOK', None
	return 'OK', auth_payload['sessionkey']

def command_proccessor(cmd):
	CURR_DIR = os.getcwd()
	data = '\x00'
	parts = cmd.split(" ")
	try:
		if(cmd == "LS"):
			data = "\n".join(os.listdir(CURR_DIR))
		elif(cmd == "PWD"):
			data = CURR_DIR+'/'
		elif(len(parts) == 2 and parts[0] == "CD"):
			path = parts[1]
			os.chdir(path)
			data = '0'
		elif(len(parts) == 4 and parts[0] == "CP"):
			fname, src, dest = parts[1], parts[2], parts[3]
			if(src[-1] == '/'):
				src = src[:-1]
			if(dest[-1] == '/'):
				dest = dest[:-1]
			osCmd = "cp "+src+"/"+fname+" "+dest
			os.system(osCmd)
			data = '0'
		elif(len(parts) == 4 and parts[0] == "MV"):
			fname, src, dest = parts[1], parts[2], parts[3]
			if(src[-1] == '/'):
				src = src[:-1]
			if(dest[-1] == '/'):
				dest = dest[:-1]
			osCmd = "mv "+src+"/"+fname+" "+dest
			os.system(osCmd)
			data = '0'
		else:
			data = "Invalid Command"
	except Exception as e:
		print "\nError :"+str(e)
		data = str(e)
	
	return data


TCP_IP = '127.0.0.1'
TCP_PORT = 5005
BUFFER_SIZE = 2048

if(len(sys.argv) == 2):
	TCP_PORT = int(sys.argv[1])
	print "Starting SSH Server at "+TCP_IP+":"+str(TCP_PORT)+'\n'
else:
	print "Invalid Input Args"
	sys.exit()

generate_RSA()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(5)

while True:
	conn, addr = s.accept()
	print 'Connection address:', addr
	
	PUBLIC_KEY = get_RSA_key('public')
	PUBLIC_KEY = base64.b64encode(PUBLIC_KEY)
	print "\nsending : ",PUBLIC_KEY
	conn.send(PUBLIC_KEY)
	
	enc_auth_payload = conn.recv(BUFFER_SIZE)
	print "\nenc auth payload:", enc_auth_payload
	PRIVATE_KEY = get_RSA_key('private')
	RSA_PRIVATE_KEY = RSA.importKey(PRIVATE_KEY)
	auth_json = RSA_PRIVATE_KEY.decrypt(ast.literal_eval(enc_auth_payload))
	auth_obj = json.loads(auth_json)
	print "\nauth obj : ", auth_obj
	auth_status, SESSION_KEY = auth(auth_obj)
	conn.send(auth_status)
	
	if(auth_status == "NOK"):
		conn.close()
		continue

	while True:
		enc_cmd = conn.recv(BUFFER_SIZE)
		if not enc_cmd:
			continue
		cmd = AES_Decrypt(enc_cmd,SESSION_KEY)
		print "\n@"+auth_obj['username']+" : "+cmd
		if(cmd == "exit"):
			break

		data = command_proccessor(cmd)

		conn.send(AES_Encrypt(data,SESSION_KEY))

	conn.close()

s.close()