No Makefile needed as its a python program

Files:
	- ssh_server.py : SSH Server
	- ssh_client.py : SSH Client
	- genpwd.py : Generates password given a passphrase

Execution Command:
	- python ssh_server.py <port>
	- python ssh_client.py
		- ssh <ipaddr> <port> <user>
		- ssh <sysname> <port> <user>
		- ssh <port> <user>
			- listfiles
			- curdir
			- chgdir <absolutepath>
			- copy <filename> <src> <dest>
			- move <filename> <src> <dest>
			- exit
		- exit	

- Program Runs Correctly
- No bugs or errors