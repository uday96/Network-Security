#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  abort();
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

void encrypt(unsigned char *hash, int keySize, char operation[],
			char algorithm[], char mode[], char inputFile[]) {

	/* Message to be encrypted */
	unsigned char *plaintext = 0;
	
	long length;
	FILE * f = fopen (inputFile, "rb");

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
	  return;
	}

	int plaintext_len = length;

  	EVP_CIPHER_CTX *ctx;

  	int len;

  	int ciphertext_len;
  	unsigned char *ciphertext = malloc(length*2);

  	char key[256], iv[256];

  	strncpy(key, hash, (keySize/8));
  	key[(keySize/8)] = '\0';

  	int blockSize = -1;

  	if(strcmp(algorithm,"AES")==0){
  		if(strcmp(mode,"CBC")==0){
  			if(keySize == 256){
  				blockSize = EVP_CIPHER_block_size(EVP_aes_256_cbc());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			    	handleErrors();
			  	ciphertext_len = len;
			  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
			  	ciphertext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)length/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else if(keySize == 192){
  				blockSize = EVP_CIPHER_block_size(EVP_aes_192_cbc());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			    	handleErrors();
			  	ciphertext_len = len;
			  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
			  	ciphertext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)length/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else if(keySize == 128){
  				blockSize = EVP_CIPHER_block_size(EVP_aes_128_cbc());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			    	handleErrors();
			  	ciphertext_len = len;
			  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
			  	ciphertext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)length/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else{
		  		printf("Please Check the Key Size\n");
		  		return;
		  	}
  		}
  		else if(strcmp(mode,"ECB")==0){
  			if(keySize == 256){
  				blockSize = EVP_CIPHER_block_size(EVP_aes_256_ecb());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			    	handleErrors();
			  	ciphertext_len = len;
			  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
			  	ciphertext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)length/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else if(keySize == 192){
  				blockSize = EVP_CIPHER_block_size(EVP_aes_192_ecb());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			    	handleErrors();
			  	ciphertext_len = len;
			  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
			  	ciphertext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)length/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else if(keySize == 128){
  				blockSize = EVP_CIPHER_block_size(EVP_aes_128_ecb());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			    	handleErrors();
			  	ciphertext_len = len;
			  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
			  	ciphertext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)length/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else{
		  		printf("Please Check the Key Size\n");
		  		return;
		  	}
  		}
  		else{
	  		printf("Please Check the Mode\n");
	  		return;
	  	}
  	}
  	else if(strcmp(algorithm,"DES")==0){
  		if(strcmp(mode,"CBC")==0){
  			if(keySize == 56){
  				blockSize = EVP_CIPHER_block_size(EVP_des_cbc());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			    	handleErrors();
			  	ciphertext_len = len;
			  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
			  	ciphertext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)length/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else{
		  		printf("Please Check the Key Size\n");
		  		return;
		  	}
  		}
  		else if(strcmp(mode,"ECB")==0){
  			if(keySize == 56){
  				blockSize = EVP_CIPHER_block_size(EVP_des_ecb());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			    	handleErrors();
			  	ciphertext_len = len;
			  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
			  	ciphertext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)length/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else{
		  		printf("Please Check the Key Size\n");
		  		return;
		  	}
  		}
  		else{
	  		printf("Please Check the Mode\n");
	  		return;
	  	}
  	}
  	else if(strcmp(algorithm,"3DES")==0){
  		if(strcmp(mode,"CBC")==0){
  			if(keySize == 112){
  				blockSize = EVP_CIPHER_block_size(EVP_des_ede_cbc());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			    	handleErrors();
			  	ciphertext_len = len;
			  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
			  	ciphertext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)length/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else if(keySize == 168){
  				blockSize = EVP_CIPHER_block_size(EVP_des_ede3_cbc());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			    	handleErrors();
			  	ciphertext_len = len;
			  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
			  	ciphertext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)length/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else{
		  		printf("Please Check the Key Size\n");
		  		return;
		  	}
  		}
  		else if(strcmp(mode,"ECB")==0){
  			if(keySize == 112){
  				blockSize = EVP_CIPHER_block_size(EVP_des_ede());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ede(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			    	handleErrors();
			  	ciphertext_len = len;
			  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
			  	ciphertext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)length/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else if(keySize == 168){
  				blockSize = EVP_CIPHER_block_size(EVP_des_ede3());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ede3(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			    	handleErrors();
			  	ciphertext_len = len;
			  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
			  	ciphertext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)length/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else{
		  		printf("Please Check the Key Size\n");
		  		return;
		  	}
  		}
  		else{
	  		printf("Please Check the Mode\n");
	  		return;
	  	}
  	}
  	else{
  		printf("Please Check the Algorithm\n");
  		return;
  	}

  	/* Clean up */
  	EVP_CIPHER_CTX_free(ctx);
  	
	FILE *encFile = fopen("enc.txt", "w");
    if (encFile != NULL) {
        fwrite(ciphertext,1,ciphertext_len,encFile);
        fclose(encFile);
    }
  	
  	return;
}

void decrypt(unsigned char *hash, int keySize, char operation[],
			char algorithm[], char mode[], char outputFile[]) {

  	/* Encrypted Message*/
	unsigned char *ciphertext = 0;

	long lengthEnc;
	FILE *encFile = fopen("enc.txt", "rb");

	if (encFile) {
	  fseek (encFile, 0, SEEK_END);
	  lengthEnc = ftell (encFile);
	  fseek (encFile, 0, SEEK_SET);
	  ciphertext = malloc (lengthEnc);
	  if (ciphertext) {
	    fread(ciphertext, 1, lengthEnc, encFile);
	  }
	  fclose (encFile);
	}

	if(!ciphertext) {
	  printf("Error reading  File\n");
	  return;
	}

	int ciphertext_len = lengthEnc;

  	EVP_CIPHER_CTX *ctx;

  	int len;

  	int plaintext_len;
  	unsigned char *plaintext = malloc(lengthEnc/2);

  	char key[256], iv[256];

  	strncpy(key, hash, (keySize/8));
  	key[(keySize/8)] = '\0';

  	int blockSize = -1;

  	if(strcmp(algorithm,"AES")==0){
  		if(strcmp(mode,"CBC")==0){
  			if(keySize == 256){
  				blockSize = EVP_CIPHER_block_size(EVP_aes_256_cbc());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
			    	handleErrors();
			  	plaintext_len = len;
			  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
			  	plaintext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)lengthEnc/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else if(keySize == 192){
  				blockSize = EVP_CIPHER_block_size(EVP_aes_192_cbc());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
			    	handleErrors();
			  	plaintext_len = len;
			  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
			  	plaintext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)lengthEnc/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else if(keySize == 128){
  				blockSize = EVP_CIPHER_block_size(EVP_aes_128_cbc());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
			    	handleErrors();
			  	plaintext_len = len;
			  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
			  	plaintext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)lengthEnc/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else{
		  		printf("Please Check the Key Size\n");
		  		return;
		  	}
  		}
  		else if(strcmp(mode,"ECB")==0){
  			if(keySize == 256){
  				blockSize = EVP_CIPHER_block_size(EVP_aes_256_ecb());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
			    	handleErrors();
			  	plaintext_len = len;
			  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
			  	plaintext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)lengthEnc/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else if(keySize == 192){
  				blockSize = EVP_CIPHER_block_size(EVP_aes_192_ecb());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
			    	handleErrors();
			  	plaintext_len = len;
			  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
			  	plaintext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)lengthEnc/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else if(keySize == 128){
  				blockSize = EVP_CIPHER_block_size(EVP_aes_128_ecb());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
			    	handleErrors();
			  	plaintext_len = len;
			  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
			  	plaintext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)lengthEnc/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else{
		  		printf("Please Check the Key Size\n");
		  		return;
		  	}
  		}
  		else{
	  		printf("Please Check the Mode\n");
	  		return;
	  	}
  	}
  	else if(strcmp(algorithm,"DES")==0){
  		if(strcmp(mode,"CBC")==0){
  			if(keySize == 56){
  				blockSize = EVP_CIPHER_block_size(EVP_des_cbc());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_DecryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
			    	handleErrors();
			  	plaintext_len = len;
			  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
			  	plaintext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)lengthEnc/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else{
		  		printf("Please Check the Key Size\n");
		  		return;
		  	}
  		}
  		else if(strcmp(mode,"ECB")==0){
  			if(keySize == 56){
  				blockSize = EVP_CIPHER_block_size(EVP_des_ecb());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ecb(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
			    	handleErrors();
			  	plaintext_len = len;
			  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
			  	plaintext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)lengthEnc/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else{
		  		printf("Please Check the Key Size\n");
		  		return;
		  	}
  		}
  		else{
	  		printf("Please Check the Mode\n");
	  		return;
	  	}
  	}
  	else if(strcmp(algorithm,"3DES")==0){
  		if(strcmp(mode,"CBC")==0){
  			if(keySize == 112){
  				blockSize = EVP_CIPHER_block_size(EVP_des_ede_cbc());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
			    	handleErrors();
			  	plaintext_len = len;
			  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
			  	plaintext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)lengthEnc/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else if(keySize == 168){
  				blockSize = EVP_CIPHER_block_size(EVP_des_ede3_cbc());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
			    	handleErrors();
			  	plaintext_len = len;
			  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
			  	plaintext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)lengthEnc/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else{
		  		printf("Please Check the Key Size\n");
		  		return;
		  	}
  		}
  		else if(strcmp(mode,"ECB")==0){
  			if(keySize == 112){
  				blockSize = EVP_CIPHER_block_size(EVP_des_ede());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ede(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
			    	handleErrors();
			  	plaintext_len = len;
			  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
			  	plaintext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)lengthEnc/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else if(keySize == 168){
  				blockSize = EVP_CIPHER_block_size(EVP_des_ede3());
		  		strncpy(iv, hash+(keySize/8), blockSize);
			  	iv[blockSize] = '\0';
			  	clock_t start = clock();
  				if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
			  	if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ede3(), NULL, key, iv))
			    	handleErrors();
			    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
			    	handleErrors();
			  	plaintext_len = len;
			  	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
			  	plaintext_len += len;
			  	clock_t end = clock();
				float seconds = (float)(end - start) / CLOCKS_PER_SEC;
				seconds = seconds/((float)lengthEnc/(float)blockSize);
				printf("%f\n",seconds*1000000);
  			}
  			else{
		  		printf("Please Check the Key Size\n");
		  		return;
		  	}
  		}
  		else{
	  		printf("Please Check the Mode\n");
	  		return;
	  	}
  	}
  	else{
  		printf("Please Check the Algorithm\n");
  		return;
  	}

  	/* Clean up */
  	EVP_CIPHER_CTX_free(ctx);

  	/* Add a NULL terminator. We are expecting printable text */
	plaintext[plaintext_len] = '\0';

	FILE *decFile = fopen(outputFile, "w");
    if (decFile != NULL) {
        fputs(plaintext, decFile);
        fclose(decFile);
    }

  	return;
}

int main(int argc, char const *argv[]) {

	int keySize = 0;
	char operation[4];
	char algorithm[5];
	char mode[4];
	char inputFile[50];
	char outputFile[50];
	if(argc != 13){
		printf("Check Input Arguments\n");
		return 0;	
	}
	
	int i=0;
	for(i=1;i<12;i+=2){
		if(strcmp(argv[i],"-p")==0){
			strcpy(operation,argv[i+1]);
		}
		else if(strcmp(argv[i],"-a")==0){
			strcpy(algorithm,argv[i+1]);
		}
		else if(strcmp(argv[i],"-m")==0){
			strcpy(mode,argv[i+1]);
		}
		else if(strcmp(argv[i],"-k")==0){
			keySize = atoi(argv[i+1]);
		}
		else if(strcmp(argv[i],"-i")==0){
			strcpy(inputFile,argv[i+1]);
		}
		else if(strcmp(argv[i],"-o")==0){
			strcpy(outputFile,argv[i+1]);
		}
	}

	char passPhrase[128];
	printf("Enter PassPhrase: ");
	scanf("%s",passPhrase);

	char hash[128];
	strcpy(hash,sha(passPhrase));

	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	if(strcmp(operation,"Enc") == 0){
		/* Encrypt the plaintext */
		encrypt (hash, keySize, operation, algorithm, mode, inputFile);
	}
	else if(strcmp(operation,"Dec") == 0){
		/* Decrypt the ciphertext */
		decrypt(hash, keySize, operation, algorithm, mode, outputFile);
	}

	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();
	
	return 0;
}
