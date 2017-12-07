#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int get_line(int sock, char *buf, int size) {
	int i = 0;
	char c = '\0';
	int n;

	while ((i < size - 1))
	{
		n = recv(sock, &c, 1, 0);
		if (n > 0 && c != '\n')
		{
			buf[i++] = c;
		}
		else {
			break;
		}
	}
	buf[i] = '\0';
	
	return i;
}

void encrypt(char *buf, int size) {

}

void decrypt(char *buf, int size) {

}

void print_md5(unsigned char *digest) {
	char md5string[33];
	for(int i = 0; i < 16; ++i)
		sprintf(&md5string[i*2], "%02x", (unsigned int)digest[i]);
	printf("md5: %s\n", md5string);
}

int write_buffer_to_file(char *buf, int size, const char *file_name) {
    FILE *fp = fopen(file_name, "wb");
    if (fp == NULL) {
        return -1;
    }

    if (fwrite(buf, 1, size, fp) != size) {
        return -1;
    }

    fclose(fp);
}

char* read_file(const char *file_name) {
	FILE *fp;
	long file_size;
	unsigned char *buffer;
	size_t result;

	if ((fp = fopen(put_name, "rb")) == NULL) {
		perror("File Error: file does not exist\n");
		exit(1);
	}

	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	rewind(fp);

	if ((buffer = (unsigned char*) malloc (sizeof(unsigned char)*file_size + 1)) == NULL) {
		die("Memory Error: ", strerror(errno));
	}

	if ((result = fread(buffer, sizeof(unsigned char), file_size + 1, fp)) != file_size) {
		die("File Error: ", strerror(errno));
	}

	buffer[file_size] = '\0';
	
	fclose(fp);
}

unsigned char* generate_md5(unsigned char *buf, int size) {
	unsigned char *md5_result;
	md5_result = (unsigned char*)malloc(sizeof(unsigned char) * (MD5_DIGEST_LENGTH+1));
	MD5(buf, size, md5_result);
	md5_result[MD5_DIGEST_LENGTH] = '\0';

	return md5_result;
}

int check_md5(unsigned char *buf, int size, unsigned char *origin_md5) {
	unsigned char *md5_result = generate_md5(buf, size);
	int result = 1;

	if (strcmp((const char*)md5_result, (const char*)origin_md5) != 0) {
		result = -1;
	}

	free(md5_result);
	return result;
}