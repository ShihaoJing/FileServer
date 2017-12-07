#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <string.h>

#define FAILURE(msg) printf("Encryption Error: %s\n", msg); \
                exit(1);

#define AES_KEYLEN 32 /* AES Key 256 bit */

void open_key_file(unsigned char **aes_key, unsigned char **aes_iv) {
    size_t read_len;
    FILE *fp;

    *aes_key = (unsigned char*)malloc(AES_KEYLEN);
    *aes_iv = (unsigned char*)malloc(AES_KEYLEN);

    if(*aes_key == NULL || *aes_iv == NULL) {
        FAILURE("mallocation failed");
    }
    
    /* read aes key */

    fp = fopen("aes_key", "r");
    if (fp == NULL) {
        free(*aes_key);
        free(*aes_iv);
        *aes_key = NULL;
        *aes_iv = NULL;
        return;
    }

    read_len = fread(*aes_key, sizeof(unsigned char), AES_KEYLEN, fp);
    if (read_len != AES_KEYLEN) {
        FAILURE("read aes key failed");
    }

    fclose(fp);

     /* read aes iv */

    fp = fopen("aes_iv", "r");
    if (fp == NULL) {
        free(*aes_key);
        free(*aes_iv);
        *aes_key = NULL;
        *aes_iv = NULL;
        return;
    }

    read_len = fread(*aes_iv, sizeof(unsigned char), AES_KEYLEN, fp);
    if (read_len != AES_KEYLEN) {
        FAILURE("read aes key failed");
    }

    fclose(fp);
}

void gen_key(unsigned char **aes_key, unsigned char **aes_iv) {
    size_t write_len;
    FILE *fp;

	// Init AES
    *aes_key = (unsigned char*)malloc(AES_KEYLEN);
    *aes_iv = (unsigned char*)malloc(AES_KEYLEN);

    if(*aes_key == NULL || *aes_iv == NULL) {
        FAILURE("mallocation failed");
	}
	
	if(RAND_bytes(*aes_key, AES_KEYLEN) == 0) {
		FAILURE("aes key gen failed");
	}

	if(RAND_bytes(*aes_iv, AES_KEYLEN) == 0) {
		FAILURE("aes iv gen failed");
    }

    /* write to aes_key */

    fp = fopen("aes_key", "wb");

    write_len = fwrite(*aes_key, sizeof(unsigned char), AES_KEYLEN, fp);
    if (write_len != AES_KEYLEN) {
        FAILURE("aes key write failed");
    }

    fclose(fp);

    /* write to aes_iv */

    fp = fopen("aes_iv", "wb");

    write_len = fwrite(*aes_iv, sizeof(unsigned char), AES_KEYLEN, fp);
    if (write_len != AES_KEYLEN) {
        FAILURE("aes iv write failed");
    }

    fclose(fp);
}

int EVP_encrypt(unsigned char *msg, int msg_len, unsigned char **enc_msg,  unsigned char *aes_key, unsigned char *aes_iv) {

    EVP_CIPHER_CTX *aesEncryptCtx = EVP_CIPHER_CTX_new();

    // Always a good idea to check if malloc failed
    if(aesEncryptCtx == NULL) {
        FAILURE("mallocation failed");
	}
    
    int block_len = 0;

    int enc_msg_len = 0;

    *enc_msg = (unsigned char*)malloc(msg_len + AES_BLOCK_SIZE);
    if(enc_msg == NULL)  {
        FAILURE("mallocation failed");
    }

    if(!EVP_EncryptInit_ex(aesEncryptCtx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv)) {
        FAILURE("aes enc contex init failed");
    }

    if(!EVP_EncryptUpdate(aesEncryptCtx, *enc_msg, &block_len, msg, msg_len)) {
        FAILURE("enc update failed");
    }

    enc_msg_len += block_len;

    if(!EVP_EncryptFinal_ex(aesEncryptCtx, *enc_msg + enc_msg_len, &block_len)) {
        FAILURE("enc final failed");
    }

    enc_msg_len += block_len;

    EVP_CIPHER_CTX_cleanup(aesEncryptCtx);

    return enc_msg_len;
}

int EVP_decrypt(unsigned char *enc_msg, int enc_msg_len, unsigned char **dec_msg,  unsigned char *aes_key, unsigned char *aes_iv) { 

    int block_len;
    int dec_msg_len = 0;


    EVP_CIPHER_CTX *aesDecryptCtx = EVP_CIPHER_CTX_new();
    // Always a good idea to check if malloc failed
    if(aesDecryptCtx == NULL) {
        FAILURE("mallocation failed");
	}

    *dec_msg = (unsigned char*)malloc(enc_msg_len);
    if (dec_msg == NULL) {
        FAILURE("mallocation failed");
    }

    if(!EVP_DecryptInit_ex(aesDecryptCtx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv)) {
        FAILURE("dec contex init failed");
    }

    if(!EVP_DecryptUpdate(aesDecryptCtx, *dec_msg, &block_len, enc_msg, enc_msg_len)) {
        FAILURE("dec update failed");
    }

    dec_msg_len += block_len;

    if(!EVP_DecryptFinal_ex(aesDecryptCtx, *dec_msg + dec_msg_len, &block_len)) {
        FAILURE("dec final failed");
    }

    dec_msg_len += block_len;

    EVP_CIPHER_CTX_cleanup(aesDecryptCtx);

    return dec_msg_len;
}