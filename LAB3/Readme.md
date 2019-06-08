No Makefile needed as its a python program

Files:
	- kerberose.py : Main Program for User Interaction
	- as.py : Authentication Server
	- tgs.py : Ticket Granting Server
	- fs.py : File Server
	- kill.py : Kill all servers
	- gen.py : Generate file structure (run before main program)

Execution Command:
	- python kerberose.py -N <#FS> <FSid>
		- get user<id[1-10]> fileserver<id[1-9]> <filename>
		- put user<id[1-10]> fileserver<id[1-9]> <filename>
		- exit	

- Program Runs Correctly
- No bugs or errors