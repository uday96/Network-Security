CC = gcc
FILES = secureMail.c
OUT_EXE = secureMail
OPSSL = -lcrypto

build: $(FILES)
		$(CC) -o $(OUT_EXE) $(FILES) $(OPSSL)

clean:
		rm -f *.o core

rebuild: clean build