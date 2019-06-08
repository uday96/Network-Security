import sys, os, base64, socket
from Crypto.Cipher import AES
import random, string, datetime

def randomword(length):
   letters = string.ascii_lowercase
   return ''.join(random.choice(letters) for i in range(length))

def getKtgs(key,IV):
	currdir = os.getcwd()
	keyfile = open(currdir+"/TGS/keys_tgs.txt",'r')
	b64ciphertext = keyfile.read()
	ciphertext = base64.b64decode(b64ciphertext)
	mode = AES.MODE_CBC
	decryptor = AES.new(key, mode, IV=IV)
	Ktgs = decryptor.decrypt(ciphertext)
	#print Ktgs
	return Ktgs

def getFSKv(fs,key,IV):
	currdir = os.getcwd()
	keyfile = open(currdir+"/TGS/keys_kv_"+fs+".txt",'r')
	b64ciphertext = keyfile.read()
	ciphertext = base64.b64decode(b64ciphertext)
	mode = AES.MODE_CBC
	decryptor = AES.new(key, mode, IV=IV)
	Kv = decryptor.decrypt(ciphertext)
	#print Kv
	return Kv

def getKctgs(Ktgs,ticket):
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	decryptor = AES.new(Ktgs, mode, IV=IV)
	cipherticket = base64.b64decode(ticket)
	ticket = decryptor.decrypt(cipherticket)
	Kctgsps = ticket.split('|')
	#print Kctgsps[1]
	return Kctgsps

def getTicketv(Kv,Kcv,parts):
	payload = parts[0]+'|'+Kcv+'|'+parts[2]+'|'+parts[3]+'|'+parts[4]+'|'+parts[5]
	while(len(payload)%16!=0):
		payload+='$'
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	encryptor = AES.new(Kv, mode, IV=IV)
	ticket = encryptor.encrypt(payload)
	b64ticket = base64.b64encode(ticket)
	#print b64ticket
	return b64ticket

def getEncDataKctgs(Kctgs,Kcv,parts):
	realmv = "realmFS"
	payload = Kcv+'|'+parts[2]+'|'+parts[3]+'|'+realmv+'|'+parts[1]
	while(len(payload)%16!=0):
		payload+='$'	
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	encryptor = AES.new(Kctgs, mode, IV=IV)
	ticket = encryptor.encrypt(payload)
	b64ticket = base64.b64encode(ticket)
	#print b64ticket
	return b64ticket

def getAuthParts(Kctgs,ticket):
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	decryptor = AES.new(Kctgs, mode, IV=IV)
	cipherticket = base64.b64decode(ticket)
	ticket = decryptor.decrypt(cipherticket)
	parts = ticket.split('|')
	#print Kctgsps[1]
	return parts

if(len(sys.argv)>=2):
	PASSWORD = sys.argv[1]		
else:
	print "Invalid Input Args"
	sys.exit()

#print "Pwd : "+PASSWORD
key = PASSWORD[:16]
IV = 16 * '\x00'

Ktgs = getKtgs(key,IV)

KcvHM = {}

currdir = os.getcwd()

s = socket.socket()         # Create a socket object
host = socket.gethostname() # Get local machine name
port = 8471                # Reserve a port for your service.
s.bind((host, port))        # Bind to the port

s.listen(5)                 # Now wait for client connection.
while True:
	c, addr = s.accept()     # Establish connection with client.
	data = c.recv(1024)
	parts = data.split('|')
	#print 'TGS : Recv req for : ', parts[1]
	
	Kv = getFSKv(parts[1],key,IV)
	KctgsParts = getKctgs(Ktgs,parts[4])
	Kctgs = KctgsParts[1]

	if(KctgsParts[4] != addr[0]):		#check ADc
		c.send("ADc mismatch")
		c.close()                # Close the connection
		continue

	authParts = getAuthParts(Kctgs,parts[5])
	if(authParts[0] != KctgsParts[3]):
		c.send("Authenticator-Ticket ID mismatch")
		c.close()                # Close the connection
		continue
	if(authParts[1] != KctgsParts[2]):
		c.send("Authenticator-Ticket Realm mismatch")
		c.close()                # Close the connection
		continue
	if(datetime.datetime.strptime(authParts[2], "%Y-%m-%d %H:%M:%S.%f") >= datetime.datetime.now()):
		c.send("Authenticator-Ticket TS error")
		c.close()                # Close the connection
		continue

	keyF = open(currdir+"/TGS/key_user_"+str(KctgsParts[3][4:])+"_tgs.txt",'w')
	b64Kctgs = base64.b64encode(Kctgs)
	keyF.write(b64Kctgs)
	keyF.close()

	Kcv = None
	if KctgsParts[3] in KcvHM:
		keyMeta = KcvHM[KctgsParts[3]]
		currTime = datetime.datetime.now()
		genTime = datetime.datetime.strptime(keyMeta[1], "%Y-%m-%d %H:%M:%S.%f")
		tdelta = (currTime - genTime).total_seconds()
		if(tdelta > 180):
			print "Kcv expired - Generating new Kcv"
			Kcv = randomword(16)
			KcvHM[parts[1]] = [Kcv,str(currTime)]
		else:
			Kcv = keyMeta[0]
	else:
		Kcv = randomword(16)
		KcvHM[parts[1]] = [Kcv,str(datetime.datetime.now())]
	#print "Kcv : "+Kcv

	Ticketv = getTicketv(Kv,Kcv,KctgsParts)
	KctgsTicket = getEncDataKctgs(Kctgs,Kcv,parts) 
	payload = KctgsParts[2]+'|'+KctgsParts[3]+'|'+Ticketv+'|'+KctgsTicket
	c.send(payload)
	c.close()                # Close the connection