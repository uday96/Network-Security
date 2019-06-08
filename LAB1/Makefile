CC = gcc
FILES = myenc.c
OUT_EXE = myenc
OPSSL = -lcrypto

build: $(FILES)
		$(CC) -o $(OUT_EXE) $(FILES) $(OPSSL)

clean:
		rm -f *.o core

rebuild: clean build