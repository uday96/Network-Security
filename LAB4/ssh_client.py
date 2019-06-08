import os, socket, base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import random, string, json

def randomword(length):
	letters = string.ascii_lowercase+string.ascii_uppercase+string.digits
	return ''.join(random.choice(letters) for i in range(length))

def AES_Encrypt(key,data):
	data = chr(0)+data
	paddint = 0
	while(len(data)%16!=0):
		data+='\x00'
		paddint+=1
	data = chr(paddint) + data[1:]
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	encryptor = AES.new(key, mode, IV=IV)
	cipherticket = encryptor.encrypt(data)
	b64cipherticket = base64.b64encode(cipherticket)
	return b64cipherticket

def AES_Decrypt(key,data):
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	decryptor = AES.new(key, mode, IV=IV)
	cipherticket = base64.b64decode(data)
	plaintext = decryptor.decrypt(cipherticket)
	paddint = ord(plaintext[0])
	plaintext = plaintext[1:-1*paddint]
	return plaintext

def command_proccessor(cmd):
	if(cmd == "listfiles"):
		return "LS"
	elif(cmd == "curdir"):
		return "PWD"
	parts = cmd.split(" ")
	if(len(parts) == 2 and parts[0] == "chgdir"):
		parts[0] = "CD"
	elif(len(parts) == 4 and parts[0] == "copy"):
		parts[0] = "CP"
	elif(len(parts) == 4 and parts[0] == "move"):
		parts[0] = "MV"
	else:
		print "Invalid Command"
		return None
	return " ".join(parts)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

BUFFER_SIZE = 2048

while True:
	cmd = raw_input(bcolors.OKBLUE+bcolors.BOLD+"Main> "+bcolors.ENDC)
	
	if(cmd == "exit"):
		break
	
	cmdParts = cmd.split(" ")
	
	if(cmdParts[0] != "ssh"):
		print "Invalid args"
		continue
	
	TCP_IP = '127.0.0.1'
	TCP_PORT = 5005
	USER = ''
	
	if(len(cmdParts) == 4):
		TCP_IP,TCP_PORT,USER = cmdParts[1],int(cmdParts[2]),cmdParts[3]
	elif(len(cmdParts) == 3):
		TCP_PORT,USER = int(cmdParts[1]),cmdParts[2]
	else:
		print "Invalid args"
		continue

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((TCP_IP, TCP_PORT))
	except Exception as e:
		print "No route to "+TCP_IP+":"+str(TCP_PORT)
		continue

	PASSPHRASE = raw_input(bcolors.HEADER+USER+"@"+TCP_IP+":"+str(TCP_PORT)+"'s password: "+bcolors.ENDC)
	
	b64_PUBLIC_KEY = s.recv(BUFFER_SIZE)
	PUBLIC_KEY = base64.b64decode(b64_PUBLIC_KEY)
	keyFile = open('server_pub.txt','w')
	keyFile.write(PUBLIC_KEY)
	keyFile.close()
	#print "\nserver pub key:", b64_PUBLIC_KEY

	RSA_PUBLIC_KEY = RSA.importKey(PUBLIC_KEY)

	SESSION_KEY = randomword(32)	#256 bit AES Session Key
	auth_obj = {
		'username': USER,
		'passphrase': PASSPHRASE,
		'sessionkey': SESSION_KEY
	}
	auth_json = json.dumps(auth_obj)
	auth_payload = RSA_PUBLIC_KEY.encrypt(auth_json, 32)
	#print "\nrsa enc auth payload: ", auth_payload
	s.send(str(auth_payload))
	
	auth_resp = s.recv(BUFFER_SIZE)
	#print "\nauth response:", auth_resp
	if(auth_resp == 'NOK'):
		s.close()
		print "Failed to connect to "+TCP_IP+":"+str(TCP_PORT)
		continue
	else:
		print "Connection to "+TCP_IP+":"+str(TCP_PORT)+" established."

	while True:
		cmd = raw_input(bcolors.OKGREEN+bcolors.BOLD+USER+"@"+TCP_IP+":"+str(TCP_PORT)+"> "+bcolors.ENDC)
		if(cmd == "exit"):
			s.send(AES_Encrypt(SESSION_KEY,cmd))
			print "logout"
			print "Connection to "+TCP_IP+":"+str(TCP_PORT)+" closed."
			break
		sshCmd = command_proccessor(cmd)
		if not sshCmd:
			continue
		s.send(AES_Encrypt(SESSION_KEY,sshCmd))
		enc_resp = s.recv(BUFFER_SIZE)
		resp = AES_Decrypt(SESSION_KEY,enc_resp)
		print resp

	s.close()
