To compile the program :
	- make

SecTypes:
	- CONF : Confidentaiality Only
	- AUIN : Authentication Only
	- COAI : Confidentiality and Authentication

Digest Algorithms:
	- sha1
	- sha256

Encryption Algorithms:
	- aes-128-ecb
	- des3
	- bf-ecb

Key Sizes:
	- AES
		- 128
	- 3DES
		- 168
	- BF
		- 128

Execution Command:
	- CreateKeys
		- ./secureMail CreateKeys <Usernames.txt>
	- CreateMail
		- ./secureMail CreateMail SecType Sender Receiver EmailInputFile EmailOutputFile DigestAlg EncryAlg
	- ReadMail
		- ./secureMail ReadMail SecType Sender Receiver SecureInputFile PlainTextOutputFile DigestAlg EncryAlg

- Program Runs Correctly
- No bugs or errors