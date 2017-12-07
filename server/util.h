#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/rand.h>

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


void print_md5(unsigned char *digest) {
	char md5string[33];
	for(int i = 0; i < 16; ++i)
		sprintf(&md5string[i*2], "%02x", (unsigned int)digest[i]);
	printf("md5: %s\n", md5string);
}

void write_file(const char *buf, int size, const char *file_name) {
    FILE *fp = fopen(file_name, "wb");
    fwrite(buf, 1, size, fp);
    fclose(fp);
}

size_t read_file(const char *file_name, char **buffer) {
	/* result is a null-terminated string*/

	FILE *fp;
	size_t file_size = 0;
	size_t result;

	if ((fp = fopen(file_name, "rb")) == NULL) {
		return 0;
	}

	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if ((*buffer = (char*) malloc(file_size)) == NULL) {
		return 0;
	}

	if ((result = fread(*buffer, sizeof(char), file_size, fp)) != file_size) {
		return 0;
	}
	
	fclose(fp);

	return file_size;
}

void generate_md5(const unsigned char *buf, size_t size, unsigned char* md5) {
	MD5(buf, size, md5);
	md5[MD5_DIGEST_LENGTH] = '\0';
}

int check_md5(unsigned char *buf, size_t size, unsigned char *origin_md5) {
	unsigned char md5[MD5_DIGEST_LENGTH+1];
	generate_md5(buf, size, md5);
	int result = 1;

	if (strcmp((const char*)md5, (const char*)origin_md5) != 0) {
		result = -1;
	}
	return result;
}