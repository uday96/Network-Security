import sys, os, base64, socket
from Crypto.Cipher import AES
import random, string, datetime

def randomword(length):
   letters = string.ascii_lowercase
   return ''.join(random.choice(letters) for i in range(length))

def getKtgs(key,IV):
	currdir = os.getcwd()
	keyfile = open(currdir+"/AS/keys_tgs.txt",'r')
	b64ciphertext = keyfile.read()
	ciphertext = base64.b64decode(b64ciphertext)
	mode = AES.MODE_CBC
	decryptor = AES.new(key, mode, IV=IV)
	Ktgs = decryptor.decrypt(ciphertext)
	#print Ktgs
	return Ktgs

def getUserKc(user,key,IV):
	currdir = os.getcwd()
	keyfile = open(currdir+"/AS/keys_kc_"+user+".txt",'r')
	b64ciphertext = keyfile.read()
	ciphertext = base64.b64decode(b64ciphertext)
	mode = AES.MODE_CBC
	decryptor = AES.new(key, mode, IV=IV)
	Kc = decryptor.decrypt(ciphertext)
	#print Kc
	return Kc

def getTickettgs(Ktgs,Kctgs,parts,adc):
	flags = "flags"
	payload = flags+'|'+Kctgs+'|'+parts[2]+'|'+parts[1]+'|'+adc+'|'+parts[4]
	while(len(payload)%16!=0):
		payload+='$'
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	encryptor = AES.new(Ktgs, mode, IV=IV)
	ticket = encryptor.encrypt(payload)
	b64ticket = base64.b64encode(ticket)
	#print b64ticket
	return b64ticket

def getEncDataKc(Kc,Kctgs,parts):
	realm = "realmTGS"
	payload = Kctgs+'|'+parts[4]+'|'+parts[5]+'|'+realm+'|'+parts[3]
	while(len(payload)%16!=0):
		payload+='$'	
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	encryptor = AES.new(Kc, mode, IV=IV)
	ticket = encryptor.encrypt(payload)
	b64ticket = base64.b64encode(ticket)
	#print b64ticket
	return b64ticket

if(len(sys.argv)>=2):
	PASSWORD = sys.argv[1]		
else:
	print "Invalid Input Args"
	sys.exit()

#print "Pwd : "+PASSWORD
key = PASSWORD[:16]
IV = 16 * '\x00'

Ktgs = getKtgs(key,IV)

currdir = os.getcwd()

KctgsHM = {}

s = socket.socket()         # Create a socket object
host = socket.gethostname() # Get local machine name
port = 6583                # Reserve a port for your service.
s.bind((host, port))        # Bind to the port

s.listen(5)                 # Now wait for client connection.
while True:
	c, addr = s.accept()     # Establish connection with client.
	data = c.recv(1024)
	parts = data.split('|')
	#print 'AS : Recv req from : ', parts[1]
	Kctgs = None
	if parts[1] in KctgsHM:
		keyMeta = KctgsHM[parts[1]]
		currTime = datetime.datetime.now()
		genTime = datetime.datetime.strptime(keyMeta[1], "%Y-%m-%d %H:%M:%S.%f")
		tdelta = (currTime - genTime).total_seconds()
		if(tdelta > 180):
			print "Kctgs expired - Generating new Kctgs"
			Kctgs = randomword(16)
			KctgsHM[parts[1]] = [Kctgs,str(currTime)]
		else:
			Kctgs = keyMeta[0]
	else:
		Kctgs = randomword(16)
		KctgsHM[parts[1]] = [Kctgs,str(datetime.datetime.now())]
	#print "Kctgs : "+Kctgs
	
	Kc = getUserKc(parts[1],key,IV)
	Ticket = getTickettgs(Ktgs,Kctgs,parts,addr[0])
	KcTicket = getEncDataKc(Kc,Kctgs,parts) 
	payload = parts[2]+'|'+parts[1]+'|'+Ticket+'|'+KcTicket
	c.send(payload)
	c.close()                # Close the connection