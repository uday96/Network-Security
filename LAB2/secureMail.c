#include <openssl/conf.h>
#include <openssl/blowfish.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

#define RSABITS 2048
#define BFKEYSIZE 128
#define DES3KEYSIZE 168
#define AESKEYSIZE 128

int padding = RSA_PKCS1_PADDING;

void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
}

void printLastError(char *msg){
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}

char* sha(char *passphrase) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char *mdString = (char *) malloc(SHA256_DIGEST_LENGTH*2+1);
    
    SHA256((unsigned char*)passphrase, strlen(passphrase), (unsigned char*)&digest);    
    int i=0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
         sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
    
    return mdString;
}

/*Refered https://stackoverflow.com/questions/5927164/how-to-generate-rsa-private-key-using-openssl*/

bool generateRSAKey(char username[]){
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;
    BIO             *bp_public = NULL, *bp_private = NULL;
 
    int             bits = RSABITS;
    unsigned long   e = RSA_F4;


    int userlen = strlen(username);
    char publicFileName[(12+userlen)];
    char privateFileName[(13+userlen)];

    strcpy(publicFileName,username);
    strcat(publicFileName,"_public.txt");
    strcpy(privateFileName,username);
    strcat(privateFileName,"_private.txt");
 
    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        goto free_all;
    }
 
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        goto free_all;
    }

    // Convert RSA to PKEY
    EVP_PKEY *pkey = EVP_PKEY_new();
    ret = EVP_PKEY_set1_RSA(pkey, r);
    if(ret != 1){
        goto free_all;
    }
 
    // 2. save public key
    bp_public = BIO_new_file(publicFileName, "w+");
    ret = PEM_write_bio_PUBKEY(bp_public, pkey);
    if(ret != 1){
        goto free_all;
    }
 
    // 3. save private key
    bp_private = BIO_new_file(privateFileName, "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

 
    // 4. free 
    free_all:

    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    EVP_PKEY_free(pkey);
    RSA_free(r);
    BN_free(bne);
 
    return (ret == 1);
}

void getUsers(char users[]){
	FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen(users, "r");
    if (fp == NULL){
    	printf("ERROR: Unable to open Usernames File\n");
    	exit(0);
    	return;
    }        

    while ((read = getline(&line, &len, fp)) != -1) {
        if(line[read-1] == '\n'){
        	line[read-1] = '\0';
        }
        generateRSAKey(line);
    }

    fclose(fp);
    return;
}

unsigned char* BlockCipherEncrypt(unsigned char *hash, unsigned char *plaintext,
				 int plaintext_len, char algorithm[], FILE *encryptedOutputFile) {


  	EVP_CIPHER_CTX *ctx;

  	int len;

  	int ciphertext_len;
  	unsigned char* ciphertext = malloc(plaintext_len*2);

  	char key[256], iv[256];

  	int blockSize = -1;
  	int keySize = -1;

  	if(strcmp(algorithm,"aes-128-ecb")==0){
  		keySize = AESKEYSIZE;
  		strncpy(key, hash, (keySize/8));
  		key[(keySize/8)] = '\0';
		blockSize = EVP_CIPHER_block_size(EVP_aes_128_ecb());
		strncpy(iv, hash+(keySize/8), blockSize);
	  	iv[blockSize] = '\0';	  	
		if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
	  	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
	    	handleErrors();
	    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
	    	handleErrors();
	  	ciphertext_len = len;
	  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	  	ciphertext_len += len;
  	}
  	else if(strcmp(algorithm,"des3")==0){
  		keySize = DES3KEYSIZE;
  		strncpy(key, hash, (keySize/8));
  		key[(keySize/8)] = '\0';
  		blockSize = EVP_CIPHER_block_size(EVP_des_ede3());
  		strncpy(iv, hash+(keySize/8), blockSize);
	  	iv[blockSize] = '\0';
	  	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
	  	if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ede3(), NULL, key, iv))
	    	handleErrors();
	    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
	    	handleErrors();
	  	ciphertext_len = len;
	  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	  	ciphertext_len += len;
  	}
  	else if(strcmp(algorithm,"bf-ecb")==0){
  		keySize = BFKEYSIZE;
  		strncpy(key, hash, (keySize/8));
  		key[(keySize/8)] = '\0';
  		blockSize = EVP_CIPHER_block_size(EVP_bf_ecb());
  		strncpy(iv, hash+(keySize/8), blockSize);
	  	iv[blockSize] = '\0';
	  	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
	  	if(1 != EVP_EncryptInit_ex(ctx, EVP_bf_ecb(), NULL, key, iv))
	    	handleErrors();
	    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
	    	handleErrors();
	  	ciphertext_len = len;
	  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	  	ciphertext_len += len;
  	}
  	else{
  		printf("Please Check the Algorithm\n");
  		exit(0);
  	}

  	//printf("%d\n",(int)ciphertext_len);
  	//printf("%d\n",(int)strlen(ciphertext));

  	//printf("Encrypted ciphertext len: %d\n",ciphertext_len );

	char *ciphertext_b64 = malloc(ciphertext_len*2);
	int ciphertext_b64_len = EVP_EncodeBlock(ciphertext_b64, ciphertext, ciphertext_len);
	//printf("b64 Encrypted ciphertext len: %d\n",ciphertext_b64_len );

	fwrite(ciphertext_b64, ciphertext_b64_len, 1, encryptedOutputFile);
    fclose(encryptedOutputFile);

  	/* Clean up */
  	EVP_CIPHER_CTX_free(ctx);
  	
	return ciphertext;
}

unsigned char* BlockCipherDecrypt(unsigned char *hash, unsigned char *ciphertext,
				 int ciphertext_len, char algorithm[], unsigned char *plaintext) {


  	EVP_CIPHER_CTX *ctx;

  	int len;

  	int plaintext_len;
  	plaintext = malloc(ciphertext_len);

  	char key[256], iv[256];

  	int blockSize = -1;
  	int keySize = -1;

  	if(strcmp(algorithm,"aes-128-ecb")==0){
  		keySize = AESKEYSIZE;
  		strncpy(key, hash, (keySize/8));
  		key[(keySize/8)] = '\0';
		blockSize = EVP_CIPHER_block_size(EVP_aes_128_ecb());
		strncpy(iv, hash+(keySize/8), blockSize);
	  	iv[blockSize] = '\0';
		if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
	  	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
	    	handleErrors();
	    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
	    	handleErrors();
	  	plaintext_len = len;
	  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
	  	plaintext_len += len;
  	}
  	else if(strcmp(algorithm,"des3")==0){
  		keySize = DES3KEYSIZE;
  		strncpy(key, hash, (keySize/8));
  		key[(keySize/8)] = '\0';
  		blockSize = EVP_CIPHER_block_size(EVP_des_ede3());
  		strncpy(iv, hash+(keySize/8), blockSize);
	  	iv[blockSize] = '\0';
	  	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
	  	if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ede3(), NULL, key, iv))
	    	handleErrors();
	    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
	    	handleErrors();
	  	plaintext_len = len;
	  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
	  	plaintext_len += len;
  	}
  	else if(strcmp(algorithm,"bf-ecb")==0){
  		keySize = BFKEYSIZE;
  		strncpy(key, hash, (keySize/8));
  		key[(keySize/8)] = '\0';
  		blockSize = EVP_CIPHER_block_size(EVP_bf_ecb());
  		strncpy(iv, hash+(keySize/8), blockSize);
	  	iv[blockSize] = '\0';
	  	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
	  	if(1 != EVP_DecryptInit_ex(ctx, EVP_bf_ecb(), NULL, key, iv))
	    	handleErrors();
	    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
	    	handleErrors();
	  	plaintext_len = len;
	  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
	  	plaintext_len += len;
  	}
  	else{
  		printf("Please Check the Algorithm\n");
  		exit(0);
  	}

  	//printf("%d\n",(int)plaintext_len);
  	//printf("%d\n",(int)strlen(plaintext));
  	plaintext[plaintext_len]='\0';
  	//printf("%d\n",(int)strlen(plaintext));

  	/* Clean up */
  	EVP_CIPHER_CTX_free(ctx);
  	
	return plaintext;
}

/*Refered http://hayageek.com/rsa-encryption-decryption-openssl-c/*/

RSA * createRSA(unsigned char * key,int public){
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL){
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public){
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else{
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL){
        printf( "Failed to create RSA");
    } 
    return rsa;
}
 
int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted){
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted){
    RSA * rsa = createRSA(key,0);
    int result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted){
    RSA * rsa = createRSA(key,0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted){
    RSA * rsa = createRSA(key,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

void conf_enc(char sender[], char receiver[], char emailInputFile[],
			 char emailOutputFile[], char digestAlg[], char encryAlg[]){

	// Generate key and iv
	char hash[128];
	strcpy(hash,sha("hash"));
	int keySize = -1;
	int blockSize = -1;
	if(strcmp(encryAlg,"aes-128-ecb")==0){
		keySize = AESKEYSIZE;
		blockSize = EVP_CIPHER_block_size(EVP_aes_128_ecb());	
	}
	else if(strcmp(encryAlg,"des3")==0){
		keySize = DES3KEYSIZE;
		blockSize = EVP_CIPHER_block_size(EVP_des_ede3());
	}
	else if(strcmp(encryAlg,"bf-ecb")==0){
		keySize = BFKEYSIZE;
		blockSize = EVP_CIPHER_block_size(EVP_bf_ecb());
	}
	char keyIv[(keySize/8)+blockSize+1];
	strncpy(keyIv,hash,((keySize/8)+blockSize));
	keyIv[(keySize/8)+blockSize]='\0';
	
	// get recievers public key file name
	int receiverlen = strlen(receiver);
    char recvPublicFileName[(12+receiverlen)];

    strcpy(recvPublicFileName,receiver);
    strcat(recvPublicFileName,"_public.txt");

	/* Read Recievers Public Key */
	unsigned char *publicKey = 0;
	
	long pubLength;
	FILE * pubFile = fopen (recvPublicFileName, "rb");

	if (pubFile) {
	  fseek (pubFile, 0, SEEK_END);
	  pubLength = ftell (pubFile);
	  fseek (pubFile, 0, SEEK_SET);
	  publicKey = malloc (pubLength);
	  if (publicKey) {
	    fread(publicKey, 1, pubLength, pubFile);
	  }
	  fclose (pubFile);
	}

	if(!pubFile) {
	  printf("Error reading publicKey File\n");
	  exit(0);
	}

	int publicKey_len = pubLength;
	unsigned char publicKeyEncrypted[10000]={};
	
	// encrypt key and iv using recievers public key
	int publicKeyEnc_length= public_encrypt(keyIv,strlen(keyIv),publicKey,publicKeyEncrypted);
	if(publicKeyEnc_length == -1){
	    printLastError("Public Encrypt failed ");
	    exit(0);
	}
	//printf("Encrypted key len: %d\n",publicKeyEnc_length);

	char *publicKeyEncrypted_b64 = malloc(publicKeyEnc_length*2);
	int publicKeyEncrypted_b64_len = EVP_EncodeBlock(publicKeyEncrypted_b64, publicKeyEncrypted, publicKeyEnc_length);

	//printf("b64 Encrypted key len: %d\n",publicKeyEncrypted_b64_len);

	/* Message to be encrypted */
	unsigned char *plaintext = 0;
	
	long length;
	FILE * f = fopen (emailInputFile, "rb");

	if (f) {
	  fseek (f, 0, SEEK_END);
	  length = ftell (f);
	  fseek (f, 0, SEEK_SET);
	  plaintext = malloc (length);
	  if (plaintext) {
	    fread (plaintext, 1, length, f);
	  }
	  fclose (f);
	}

	if(!plaintext) {
	  printf("Error reading input File\n");
	  exit(0);
	}

	int plaintext_len = length;
	//printf("Plaintext length: %d\n", plaintext_len);

	// write encrypted contents into file
	FILE *encryptedOutputFile = fopen(emailOutputFile, "w");
    if (encryptedOutputFile != NULL) {
        fwrite(publicKeyEncrypted_b64 , publicKeyEncrypted_b64_len , 1 , encryptedOutputFile);
        fwrite("\n" , 1 , 1 , encryptedOutputFile);
    }

	BlockCipherEncrypt(hash, plaintext, plaintext_len, encryAlg, encryptedOutputFile);
}

void conf_dec(char sender[], char receiver[], char secureInputFile[],
			 char plainTextOutputFile[], char digestAlg[], char encryAlg[]){

	// get recievers private key file name
	int receiverlen = strlen(receiver);
    char recvPrivateFileName[(13+receiverlen)];

    strcpy(recvPrivateFileName,receiver);
    strcat(recvPrivateFileName,"_private.txt");

	/* Read Recievers Private Key */
	unsigned char *privateKey = 0;
	
	long privLength;
	FILE * privFile = fopen (recvPrivateFileName, "rb");

	if (privFile) {
	  fseek (privFile, 0, SEEK_END);
	  privLength = ftell (privFile);
	  fseek (privFile, 0, SEEK_SET);
	  privateKey = malloc (privLength);
	  if (privateKey) {
	    fread(privateKey, 1, privLength, privFile);
	  }
	  fclose (privFile);
	}
	if(!privFile) {
	  printf("Error reading privateKey File\n");
	  exit(0);
	}
	int privateKey_len = privLength;

	/* Read Encrypted Input */
	FILE * encFile = fopen (secureInputFile, "rb");
	if(!encFile) {
	  printf("Error reading secureInputFile\n");
	  exit(0);
	}

	char *keyEnc_b64;
    size_t bufsize = 1024;
    size_t keyEnc_b64_len;
    keyEnc_b64 = (char *)malloc(bufsize * sizeof(char));
	fgets(keyEnc_b64,bufsize,encFile);
	keyEnc_b64_len = strlen(keyEnc_b64);
	if(keyEnc_b64[keyEnc_b64_len-1]=='\n'){
		keyEnc_b64[keyEnc_b64_len-1]='\0';
		keyEnc_b64_len--;
	}
	//printf("b64 encrypted key len: %d\n",(int)keyEnc_b64_len );

	char *dataEnc_b64;
    bufsize = 10000;
    size_t dataEnc_b64_len;
    dataEnc_b64 = (char *)malloc(bufsize * sizeof(char));
	fgets(dataEnc_b64,bufsize,encFile);
	dataEnc_b64_len = strlen(dataEnc_b64);
	
	char* keyEnc = malloc(keyEnc_b64_len*2);
	int keyEnc_len = EVP_DecodeBlock(keyEnc, keyEnc_b64, keyEnc_b64_len);
	int temp = keyEnc_len-1;
	for(temp = keyEnc_len-1;temp>=0;temp--){
		if(keyEnc[temp]=='\0' && temp >= (RSABITS/8)){
			keyEnc_len--;
		}
	}
	//printf("encrypted key len: %d\n",keyEnc_len );

	char* dataEnc = malloc(dataEnc_b64_len*2);
	int dataEnc_len = EVP_DecodeBlock(dataEnc, dataEnc_b64, dataEnc_b64_len);
	int dataEnc_len_init = dataEnc_len;
	if(dataEnc_b64[dataEnc_b64_len-1]=='='){
			dataEnc_len--;
	}
	if(dataEnc_b64[dataEnc_b64_len-2]=='='){
			dataEnc_len--;
	}
	//printf("encrypted data len init: %d\n",dataEnc_len_init );
	//printf("encrypted data len: %d\n",dataEnc_len );

	unsigned char decryptedKey[10000]={};

	int decryptedKey_length = private_decrypt(keyEnc, keyEnc_len, privateKey, decryptedKey);
	if(decryptedKey_length == -1){
	    printLastError("Private Decrypt failed ");
	    exit(0);
	}
	//printf("Decrypted Key: %s\n",decryptedKey);

	// decrypt message using input algo and decrypted rsa key
	char *plaintext;
	plaintext = BlockCipherDecrypt(decryptedKey, dataEnc, dataEnc_len, encryAlg, plaintext);

	// write decrypted contents into file
	FILE *decryptedOutputFile = fopen(plainTextOutputFile, "w");
    if (decryptedOutputFile != NULL) {
        fputs(plaintext , decryptedOutputFile);
        fclose(decryptedOutputFile);
    }

}

void auin_enc(char sender[], char receiver[], char emailInputFile[],
			 char emailOutputFile[], char digestAlg[], char encryAlg[]){

	/* Message to be encrypted */
	unsigned char *plaintext = 0;
	
	long length;
	FILE * f = fopen (emailInputFile, "rb");

	if (f) {
	  fseek (f, 0, SEEK_END);
	  length = ftell (f);
	  fseek (f, 0, SEEK_SET);
	  plaintext = malloc (length);
	  if (plaintext) {
	    fread (plaintext, 1, length, f);
	  }
	  fclose (f);
	}

	if(!plaintext) {
	  printf("Error reading input File\n");
	  exit(0);
	}

	int plaintext_len = length;
	//printf("Plaintext length: %d\n", plaintext_len);


	// Generate Message Digest
	char hash[128];
	if(strcmp(digestAlg,"sha1")==0){
		SHA1(plaintext,plaintext_len,hash);
	}
	else if(strcmp(digestAlg,"sha256")==0){
		SHA256(plaintext,plaintext_len,hash);
	}
	//printf("Msg Digest : %s\n", hash);
	//printf("Msg Digest len: %d\n", (int)strlen(hash));

	// get senders private key file name
	int senderlen = strlen(sender);
    char senderPrivateFileName[(13+senderlen)];

    strcpy(senderPrivateFileName,sender);
    strcat(senderPrivateFileName,"_private.txt");

	/* Read Senders Private Key */
	unsigned char *privateKey = 0;
	
	long privLength;
	FILE * privFile = fopen (senderPrivateFileName, "rb");
	if (privFile) {
	  fseek (privFile, 0, SEEK_END);
	  privLength = ftell (privFile);
	  fseek (privFile, 0, SEEK_SET);
	  privateKey = malloc (privLength);
	  if (privateKey) {
	    fread(privateKey, 1, privLength, privFile);
	  }
	  fclose (privFile);
	}
	if(!privFile) {
	  printf("Error reading privateKey File\n");
	  exit(0);
	}
	int privateKey_len = privLength;

	// RSA encrypt the digest using senders private key
	unsigned char encryptedDigest[10000]={};
	int encryptedDigest_length= private_encrypt(hash,strlen(hash),privateKey,encryptedDigest);
	if(encryptedDigest_length == -1){
	    printLastError("Private Encrypt failed");
	    exit(0);
	}
	//printf("Encrypted Digest length = %d\n",encryptedDigest_length);

	char *encryptedDigest_b64 = malloc(encryptedDigest_length*2);
	int encryptedDigest_b64_len = EVP_EncodeBlock(encryptedDigest_b64, encryptedDigest, encryptedDigest_length);
	//printf("b64 Encrypted Digest len: %d\n",encryptedDigest_b64_len );

	char *encryptedMsg_b64 = malloc(plaintext_len*2);
	int encryptedMsg_b64_len = EVP_EncodeBlock(encryptedMsg_b64, plaintext, plaintext_len);
	//printf("b64 Encrypted Plaintext len: %d\n",encryptedMsg_b64_len );

	// write encrypted contents into file
	FILE *encryptedOutputFile = fopen(emailOutputFile, "w");
    if (encryptedOutputFile != NULL) {
        fputs(encryptedDigest_b64, encryptedOutputFile);
        fputc('\n', encryptedOutputFile);
        fputs(encryptedMsg_b64, encryptedOutputFile);
        fclose(encryptedOutputFile);
    }

}

void auin_dec(char sender[], char receiver[], char secureInputFile[],
			 char plainTextOutputFile[], char digestAlg[], char encryAlg[]){

	// get senders public key file name
	int senderlen = strlen(sender);
    char senderPublicFileName[(12+senderlen)];

    strcpy(senderPublicFileName,sender);
    strcat(senderPublicFileName,"_public.txt");

	/* Read Senders Public Key */
	unsigned char *publicKey = 0;
	
	long pubLength;
	FILE * pubFile = fopen (senderPublicFileName, "rb");
	if (pubFile) {
	  fseek (pubFile, 0, SEEK_END);
	  pubLength = ftell (pubFile);
	  fseek (pubFile, 0, SEEK_SET);
	  publicKey = malloc (pubLength);
	  if (publicKey) {
	    fread(publicKey, 1, pubLength, pubFile);
	  }
	  fclose (pubFile);
	}
	if(!pubFile) {
	  printf("Error reading privateKey File\n");
	  exit(0);
	}
	int publicKey_len = pubLength;

	// /* Read Encrypted Input */
	FILE * encFile = fopen (secureInputFile, "rb");
	if(!encFile) {
	  printf("Error reading secureInputFile\n");
	  exit(0);
	}

	// Read b64 digest
	char *digestEnc_b64;
    size_t bufsize = 1024;
    size_t digestEnc_b64_len;
    digestEnc_b64 = (char *)malloc(bufsize * sizeof(char));
	digestEnc_b64_len = getline(&digestEnc_b64,&bufsize,encFile);
	if(digestEnc_b64[digestEnc_b64_len-1]=='\n'){
		digestEnc_b64[digestEnc_b64_len-1]='\0';
		digestEnc_b64_len--;
	}

	// Read b64 digest
	char *msgEnc_b64;
    bufsize = 10000;
    size_t msgEnc_b64_len;
    msgEnc_b64 = (char *)malloc(bufsize * sizeof(char));
	msgEnc_b64_len = getline(&msgEnc_b64,&bufsize,encFile);
	if(msgEnc_b64[msgEnc_b64_len-1]=='\n'){
		msgEnc_b64[msgEnc_b64_len-1]='\0';
		msgEnc_b64_len--;
	}
  	fclose (encFile);

  	char* plaintext = malloc(msgEnc_b64_len);
	int plaintext_len = EVP_DecodeBlock(plaintext, msgEnc_b64, msgEnc_b64_len);
	int temp = plaintext_len-1;
	for(temp = plaintext_len-1;temp>=0;temp--){
		if(plaintext[temp]=='\0'){
			plaintext_len--;
		}
	}
	//printf("plaintext len: %d\n",plaintext_len );
	
	char* digestEnc = malloc(digestEnc_b64_len);
	int digestEnc_len = EVP_DecodeBlock(digestEnc, digestEnc_b64, digestEnc_b64_len);
	temp = digestEnc_len-1;
	for(temp = digestEnc_len-1;temp>=0;temp--){
		if(digestEnc[temp]=='\0' && temp >= (RSABITS/8)){
			digestEnc_len--;
		}
	}
	//printf("rsa encrypted digest len: %d\n",digestEnc_len );

	unsigned char decrypted[10000]={};

	int decrypted_length = public_decrypt(digestEnc,digestEnc_len,publicKey, decrypted);
	if(decrypted_length == -1){
	    printLastError("Authentication Failed");
	    exit(0);
	}
	//printf("rsa decrypted digest length =%d\n",decrypted_length);

	// Generate Message Digest
	char hash[128];
	if(strcmp(digestAlg,"sha1")==0){
		SHA1(plaintext,plaintext_len,hash);
	}
	else if(strcmp(digestAlg,"sha256")==0){
		SHA256(plaintext,plaintext_len,hash);
	}
	//printf("Msg Digest : %s\n", hash);
	//printf("Msg Digest len: %d\n", (int)strlen(hash));

	if(strcmp(hash,decrypted)==0){
		printf("success\n");
		// write plaintext into file
		FILE *outputFile = fopen(plainTextOutputFile, "w");
	    if (outputFile != NULL) {
	        fputs(plaintext, outputFile);
	        fclose(outputFile);
	    }
	}
	else{
		printf("failure\n");
	}
    return;
}

void coai_enc(char sender[], char receiver[], char emailInputFile[],
			 char emailOutputFile[], char digestAlg[], char encryAlg[]){

	auin_enc(sender, receiver, emailInputFile, emailOutputFile, digestAlg, encryAlg);
	conf_enc(sender, receiver, emailOutputFile, emailOutputFile, digestAlg, encryAlg);
}

void coai_dec(char sender[], char receiver[], char secureInputFile[],
			 char plainTextOutputFile[], char digestAlg[], char encryAlg[]){

	conf_dec(sender, receiver, secureInputFile, plainTextOutputFile, digestAlg, encryAlg);
	auin_dec(sender, receiver, plainTextOutputFile, plainTextOutputFile, digestAlg, encryAlg);
}

int main(int argc, char const *argv[]) {
	
	char mode[10];
	char usernamesFileName[20];
	char secType[5];
	char sender[20];
	char receiver[20];
	char emailInputFile[20];
	char emailOutputFile[20];
	char digestAlg[7];
	char encryAlg[12];

	if((argc == 3) && (strcmp(argv[1],"CreateKeys")==0)){
		strcpy(mode,argv[1]);
		strcpy(usernamesFileName,argv[2]);
	}
	else if((argc == 9) && ((strcmp(argv[1],"CreateMail")==0) || (strcmp(argv[1],"ReadMail")==0))){
		strcpy(mode,argv[1]);
		strcpy(secType,argv[2]);
		strcpy(sender,argv[3]);
		strcpy(receiver,argv[4]);
		strcpy(emailInputFile,argv[5]);
		strcpy(emailOutputFile,argv[6]);
		strcpy(digestAlg,argv[7]);
		strcpy(encryAlg,argv[8]);
	}

	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	if(strcmp(mode,"CreateKeys")==0){
		getUsers(usernamesFileName);
	}
	else if(strcmp(mode,"CreateMail")==0){
		if(strcmp(secType,"CONF")==0){
			conf_enc(sender, receiver, emailInputFile,
			 emailOutputFile, digestAlg, encryAlg);
		}
		else if(strcmp(secType,"AUIN")==0){
			auin_enc(sender, receiver, emailInputFile,
			 emailOutputFile, digestAlg, encryAlg);
		}
		else if(strcmp(secType,"COAI")==0){
			coai_enc(sender, receiver, emailInputFile,
			 emailOutputFile, digestAlg, encryAlg);
		}
	}
	else if(strcmp(mode,"ReadMail")==0){
		if(strcmp(secType,"CONF")==0){
			conf_dec(sender, receiver, emailInputFile,
			 emailOutputFile, digestAlg, encryAlg);
		}
		else if(strcmp(secType,"AUIN")==0){
			auin_dec(sender, receiver, emailInputFile,
			 emailOutputFile, digestAlg, encryAlg);
		}
		else if(strcmp(secType,"COAI")==0){
			coai_dec(sender, receiver, emailInputFile,
			 emailOutputFile, digestAlg, encryAlg);
		}
	}
	return 0;
}