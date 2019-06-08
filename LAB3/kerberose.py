import sys, os, socket, base64
from Crypto.Cipher import AES
import random, string, datetime

def randomword(length):
   letters = string.ascii_lowercase
   return ''.join(random.choice(letters) for i in range(length))

def auth(user):
	options = "options"
	realm = "realmUser"
	idTGS = "tgs"
	times = "times"
	nonce = str(random.randint(1,100))
	payload = options+'|'+user+'|'+realm+'|'+idTGS+'|'+times+'|'+nonce
	s = socket.socket()         # Create a socket object
	host = socket.gethostname() # Get local machine name
	port = 6583                # Reserve a port for your service.
	s.connect((host, port))
	s.send(payload)
	data = s.recv(1024)
	s.close()                     # Close the socket when done
	#print data
	
	parts = data.split('|')
	ticket = parts[2]
	encData = base64.b64decode(parts[3])

	currdir = os.getcwd()
	keyfile = open(currdir+"/"+user+"/key",'r')
	b64Kc = keyfile.read()
	Kc = base64.b64decode(b64Kc)
	mode = AES.MODE_CBC
	IV = 16 * '\x00'
	decryptor = AES.new(Kc, mode, IV=IV)
	plainpayload = decryptor.decrypt(encData)
	plainpayloadParts = plainpayload.split('|')
	Kctgs = plainpayloadParts[0]
	#print "Kctgs : "+Kctgs

	keyF = open(currdir+"/"+user+"/key_user_"+str(user[4:])+"_tgs.txt",'w')
	b64Kctgs = base64.b64encode(Kctgs)
	keyF.write(b64Kctgs)
	keyF.close()

	isError = False
	if(plainpayloadParts[2] != nonce):
		isError = True
		print "Nonce mismatch"
	if(parts[0] != realm):
		isError = True
		print "Realm mismatch"
	if(parts[1] != user):
		isError = True
		print "UserID mismatch"

	return ticket, Kctgs, isError

def tgs(Kctgs,ticket,user,fs):
	options = "options"
	realm = "realmUser"
	times = "times"
	nonce = str(random.randint(1,100))
	ts = str(datetime.datetime.now())

	authpayload = user+'|'+realm+'|'+ts+'|'
	while(len(authpayload)%16!=0):
		authpayload+='$'	
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	encryptor = AES.new(Kctgs, mode, IV=IV)
	authenticator = encryptor.encrypt(authpayload)
	b64authenticator = base64.b64encode(authenticator)

	payload = options+'|'+fs+'|'+times+'|'+nonce+'|'+ticket+'|'+b64authenticator

	s = socket.socket()         # Create a socket object
	host = socket.gethostname() # Get local machine name
	port = 8471                # Reserve a port for your service.
	s.connect((host, port))
	s.send(payload)
	data = s.recv(1024)
	s.close()                     # Close the socket when done
	#print data

	errs = ["ADc mismatch","Authenticator-Ticket ID mismatch","Authenticator-Ticket Realm mismatch","Authenticator-Ticket TS error"]
	if(data in errs):
		print data
		return None, None, None

	parts = data.split('|')
	ticketv = parts[2]
	encData = base64.b64decode(parts[3])

	mode = AES.MODE_CBC
	IV = 16 * '\x00'
	decryptor = AES.new(Kctgs, mode, IV=IV)
	plainpayload = decryptor.decrypt(encData)
	plainpayloadParts = plainpayload.split('|')
	Kcv = plainpayloadParts[0]
	#print "Kcv : "+Kcv

	currdir = os.getcwd()
	keyF = open(currdir+"/"+user+"/key_user_"+str(user[4:])+"_fs_"+str(fs[-1])+".txt",'w')
	b64Kcv = base64.b64encode(Kcv)
	keyF.write(b64Kcv)
	keyF.close()

	isError = False
	if(plainpayloadParts[2] != nonce):
		isError = True
		print "Nonce mismatch"
	if(parts[0] != realm):
		isError = True
		print "Realm mismatch"
	if(parts[1] != user):
		isError = True
		print "UserID mismatch"

	return ticketv, Kcv, isError

def subkeyauth(Kcv,ticketv,user,fs):
	options = "auth"
	realm = "realmUser"
	ts2 = str(datetime.datetime.now())
	seq = "seq#"
	subKey = randomword(16)
	#print "subKey : "+subKey

	authpayload = user+'|'+realm+'|'+ts2+'|'+subKey+'|'+seq+'|'
	while(len(authpayload)%16!=0):
		authpayload+='$'	
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	encryptor = AES.new(Kcv, mode, IV=IV)
	authenticator = encryptor.encrypt(authpayload)
	b64authenticator = base64.b64encode(authenticator)

	payload = options+'|'+ticketv+'|'+b64authenticator

	s = socket.socket()         # Create a socket object
	host = socket.gethostname() # Get local machine name
	port = 8680+int(fs[-1])                # Reserve a port for your service.
	s.connect((host, port))
	s.send(payload)
	data = s.recv(1024)
	s.close()                     # Close the socket when done
	#print data

	errs = ["ADc mismatch","Authenticator-Ticket ID mismatch","Authenticator-Ticket Realm mismatch","Authenticator-Ticket TS error"]
	if(data in errs):
		print data
		return None

	encData = base64.b64decode(data)

	mode = AES.MODE_CBC
	IV = 16 * '\x00'
	decryptor = AES.new(Kcv, mode, IV=IV)
	plainpayload = decryptor.decrypt(encData)
	finalSubKey = plainpayload.split('|')[1]
	#print "Final SubKey : "+finalSubKey

	return finalSubKey

def getFile(user,fs,filename,subKey):
	msg = "get|"+filename+"|"
	while(len(msg)%16!=0):
		msg+='$'	
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	encryptor = AES.new(subKey, mode, IV=IV)
	encMsg = encryptor.encrypt(msg)
	b64encMsg = base64.b64encode(encMsg)

	payload = "filetransfer|"+user+"|"+b64encMsg

	s = socket.socket()         # Create a socket object
	host = socket.gethostname() # Get local machine name
	port = 8680+int(fs[-1])                # Reserve a port for your service.
	s.connect((host, port))
	s.send(payload)
	data = s.recv(1024)
	s.close()                     # Close the socket when done
	#print data

	if(data == "file not found" or data == "subKey not found"):
		print data
		return

	currdir = os.getcwd()
	encFname = ""
	if(filename[-3:]=="txt"):
		encFname = filename[:-3]+"enc"
	else:
		encFname = filename+".enc"
	f = open(currdir+"/"+user+"/"+encFname,"w")
	f.write(data)
	f.close()

	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	decryptor = AES.new(subKey, mode, IV=IV)
	encData = base64.b64decode(data)
	plaintext = decryptor.decrypt(encData)
	paddint = ord(plaintext[0])
	plaintext = plaintext[1:-1*paddint]
	print plaintext
	f = open(currdir+"/"+user+"/"+filename,"w")
	f.write(plaintext)
	f.close()
	
	return

def putFile(user,fs,filename,subKey):
	currdir = os.getcwd()
	fdata = ""
	try:
		#print currdir+"/"+user+"/"+filename
		file = open(currdir+"/"+user+"/"+filename)
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
		fdata = base64.b64encode(encFdata)
	except Exception as e:
		#print str(e)
		print "file not found"
		return
	msg = "put|"+filename+"|"+fdata+"|"
	while(len(msg)%16!=0):
		msg+='$'	
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	encryptor = AES.new(subKey, mode, IV=IV)
	encMsg = encryptor.encrypt(msg)
	b64encMsg = base64.b64encode(encMsg)

	payload = "filetransfer|"+user+"|"+b64encMsg

	s = socket.socket()         # Create a socket object
	host = socket.gethostname() # Get local machine name
	port = 8680+int(fs[-1])                # Reserve a port for your service.
	s.connect((host, port))
	s.send(payload)
	data = s.recv(1024)
	s.close()                     # Close the socket when done
	#print data
	return


if(sys.argv[1] == "-N"):
	if(len(sys.argv)-3 != int(sys.argv[2])):
		print "Invalid Input Args"
		sys.exit()
else:
	print "Invalid Input Args"
	sys.exit()

key = '0123456789abcdef'
PASSWORD = key

ports = "6583 8471"

os.system("python as.py "+PASSWORD+" &")
os.system("python tgs.py "+PASSWORD+" &")

for FSid in sys.argv[3:]:
	ports += " 868"+FSid[-1]
	os.system("python fs.py "+FSid[-1]+" &")

while True:	
	cmd = raw_input("ker5>")
	if(cmd=="exit"):
		os.system("python kill.py "+ports)
		break
	parts = cmd.split(' ')
	user = parts[1]
	fs = parts[2]
	fs = fs.replace("fileserver","FS")
	filename = parts[3]
	ticket,Kctgs,isError = auth(user)
	if(isError):
		continue
	ticketv,Kcv,isError = tgs(Kctgs,ticket,user,fs)
	if(isError):
		continue
	subKey = subkeyauth(Kcv,ticketv,user,fs)
	if(not subKey):
		continue
	if(parts[0] == "get"):
		getFile(user,fs,filename,subKey)
	elif(parts[0] == "put"):
		putFile(user,fs,filename,subKey)
