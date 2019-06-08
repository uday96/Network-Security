import sys, os, base64, socket, datetime
from Crypto.Cipher import AES

def getFSKv(fs):
	currdir = os.getcwd()
	keyfile = open(currdir+"/"+fs+"/key",'r')
	b64Kv = keyfile.read()
	Kv = base64.b64decode(b64Kv)
	#print "Kv : "+Kv
	return Kv

def getKcv(Kv,ticket):
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	decryptor = AES.new(Kv, mode, IV=IV)
	cipherticket = base64.b64decode(ticket)
	ticket = decryptor.decrypt(cipherticket)
	Kcv = ticket.split('|')
	#print "Kcv : "+Kcv
	return Kcv

def getSubKeyParts(Kcv,ticket):
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	decryptor = AES.new(Kcv, mode, IV=IV)
	cipherticket = base64.b64decode(ticket)
	ticket = decryptor.decrypt(cipherticket)
	subKeyparts = ticket.split('|')
	return subKeyparts

def getFilename(subKey,ticket):
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	decryptor = AES.new(subKey, mode, IV=IV)
	cipherticket = base64.b64decode(ticket)
	ticket = decryptor.decrypt(cipherticket)
	parts = ticket.split('|')
	#print "FS : Req : "+parts[0]+" "+parts[1]
	return parts[0],parts[1],parts[2]

ID = 0
if(len(sys.argv)>=2):
	ID = int(sys.argv[1])
else:
	print "Invalid Input Args"
	sys.exit()

#print "FSid : "+str(ID)

subKeysHM = {}

currdir = os.getcwd()

s = socket.socket()         # Create a socket object
host = socket.gethostname() # Get local machine name
port = 8680+ID                # Reserve a port for your service.
s.bind((host, port))        # Bind to the port

s.listen(5)                 # Now wait for client connection.
while True:
	c, addr = s.accept()     # Establish connection with client.
	data = c.recv(1024)
	parts = data.split('|')
	if(parts[0] == "auth"):
		Kv = getFSKv("FS"+str(ID))
		KcvParts = getKcv(Kv,parts[1])
		Kcv = KcvParts[1]

		subKeyparts = getSubKeyParts(Kcv,parts[2])

		if(KcvParts[4] != addr[0]):		#check ADc
			c.send("ADc mismatch")
			c.close()                # Close the connection
			continue

		if(subKeyparts[0] != KcvParts[3]):
			c.send("Authenticator-Ticket ID mismatch")
			c.close()                # Close the connection
			continue
		if(subKeyparts[1] != KcvParts[2]):
			c.send("Authenticator-Ticket Realm mismatch")
			c.close()                # Close the connection
			continue
		if(datetime.datetime.strptime(subKeyparts[2], "%Y-%m-%d %H:%M:%S.%f") >= datetime.datetime.now()):
			c.send("Authenticator-Ticket TS error")
			c.close()                # Close the connection
			continue

		keyF = open(currdir+"/FS"+str(ID)+"/"+subKeyparts[0]+"/key_user_"+str(subKeyparts[0][4:])+"_fs_"+str(ID)+".txt",'w')
		b64Kcv = base64.b64encode(Kcv)
		keyF.write(b64Kcv)
		keyF.close()

		payload = subKeyparts[2]+'|'+subKeyparts[3]+'|'+subKeyparts[4]
		while(len(payload)%16!=0):
			payload+='$'	
		IV = 16 * '\x00'
		mode = AES.MODE_CBC
		encryptor = AES.new(Kcv, mode, IV=IV)
		ticket = encryptor.encrypt(payload)
		b64ticket = base64.b64encode(ticket)
		subKeysHM[subKeyparts[0]] = [subKeyparts[3],subKeyparts[2]]
		c.send(b64ticket)
	elif(parts[0] == "filetransfer"):
		user = parts[1]
		data = ""
		if user not in subKeysHM:
			data = "subKey not found"
		else:
			subKey = subKeysHM[user][0]
			del subKeysHM[user]
			operation,filename,putfdata = getFilename(subKey,parts[2])
			if(operation == "get"):
				try:
					#print currdir+"/FS"+str(ID)+"/"+user+"/"+filename
					file = open(currdir+"/FS"+str(ID)+"/"+user+"/"+filename)
					fdata = chr(0)
					fdata += file.read()
					paddint = 0
					while(len(fdata)%16!=0):
						paddint+=1
						fdata+='$'
					fdata = chr(paddint)+fdata[1:]
					IV = 16 * '\x00'
					mode = AES.MODE_CBC
					encryptor = AES.new(subKey, mode, IV=IV)
					encFdata = encryptor.encrypt(fdata)
					data = base64.b64encode(encFdata)
				except Exception as e:
					#print str(e)
					data = "file not found"
			elif(operation == "put"):
				encFname = ""
				if(filename[-3:]=="txt"):
					encFname = filename[:-3]+"enc"
				else:
					encFname = filename+".enc"
				f = open(currdir+"/FS"+str(ID)+"/"+user+"/"+encFname,"w")
				f.write(putfdata)
				f.close()
				IV = 16 * '\x00'
				mode = AES.MODE_CBC
				decryptor = AES.new(subKey, mode, IV=IV)
				encfdata = base64.b64decode(putfdata)
				plaintext = decryptor.decrypt(encfdata)
				paddint = ord(plaintext[0])
				plaintext = plaintext[1:-1*paddint]
				#print plaintext
				f = open(currdir+"/FS"+str(ID)+"/"+user+"/"+filename,"w")
				f.write(plaintext)
				f.close()
				data = "File Recieved Successfully!"
		c.send(data)
	c.close()                # Close the connection