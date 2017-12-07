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
#include <assert.h>
#include "crypto.h"
#include "util.h"
#include "buffer.h"
#include "support.h"
#include "Client.h"

#define MAX_BUF_LENGTH 1024

void help(char *progname)
{
	printf("Usage: %s [OPTIONS]\n", progname);
	printf("Perform a PUT or a GET from a network file server\n");
	printf("  -P    PUT file indicated by parameter\n");
	printf("  -G    GET file indicated by parameter\n");
	printf("  -s    server info (IP or hostname)\n");
	printf("  -p    port on which to contact server\n");
	printf("  -S    for GETs, name to use when saving file locally\n");
}


void die(const char *msg1, const char *msg2)
{
	fprintf(stderr, "%s, %s\n", msg1, msg2);
	exit(0);
}


/*
 * connect_to_server() - open a connection to the server specified by the
 *                       parameters
 */
int connect_to_server(char *server, int port)
{
	int clientfd;
	struct hostent *hp;
	struct sockaddr_in serveraddr;
	char errbuf[256];                                   /* for errors */

	/* create a socket */
	if((clientfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		die("Error creating socket: ", strerror(errno));
	}

	/* Fill in the server's IP address and port */
	if((hp = gethostbyname(server)) == NULL)
	{
		sprintf(errbuf, "%d", h_errno);
		die("DNS error: DNS error ", errbuf);
	}
	bzero((char *) &serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	bcopy((char *)hp->h_addr_list[0], (char *)&serveraddr.sin_addr.s_addr, hp->h_length);
	serveraddr.sin_port = htons(port);

	/* connect */
	if(connect(clientfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
	{
		die("Error connecting: ", strerror(errno));
	}
	return clientfd;
}

/*
 * put_file() - send a file to the server accessible via the given socket fd
 */
void put_file(int fd, char *put_name, int check_sum)
{
	/* TODO: implement a proper solution, instead of calling the echo() client */

	/* Open file, get size of file, and read content of file into a buffer*/

	Buffer request_buffer;
	char md5[MD5_DIGEST_LENGTH+1];

	size_t file_size;
	char   *buffer;

	file_size = read_file(put_name, &buffer);

	if (file_size == 0) {
		die("File Error", strerror(errno));
	}

	generate_md5((unsigned char*)buffer, file_size, (unsigned char*)md5);

	if (check_sum) {
		request_buffer.appendf("PUTC %s\n", put_name);
	}
	else {
		request_buffer.appendf("PUT %s\n", put_name);
	}
	
	request_buffer.appendf("%lu\n", file_size);

	if (check_sum) {
		request_buffer.appendf("%s\n", md5);
		print_md5((unsigned char*)md5);
	}

	request_buffer.append(buffer, file_size);
	free(buffer);
	
	const char *request = request_buffer.get_c_str();

	/* send request to the server, handling short counts */
	size_t total_bytes      = strlen(request);
	size_t bytes_to_send    = total_bytes;
	size_t bytes_sent       = 0;
	
	while(bytes_to_send > 0)
	{
		if((bytes_sent = write(fd, request, bytes_to_send)) <= 0)
		{
			die("write Error: ", strerror(errno));
			exit(0);
		}
		bytes_to_send -= bytes_sent;
		request += bytes_sent;
	}

	//printf("client send %lu bytes to server\n", total_bytes);

	/* get response from server */

	char read_buffer[MAX_BUF_LENGTH];
	size_t bytes_received;

	bytes_received = get_line(fd, read_buffer, sizeof(read_buffer));

	printf("Response: %s\n", read_buffer);	
}

/*
 * get_file() - get a file from the server accessible via the given socket
 *              fd, and save it according to the save_name
 */
void get_file(int fd, char *get_name, char *save_name, int check_sum)
{
	/* TODO: implement a proper solution, instead of calling the echo() client */
	char buf[MAX_BUF_LENGTH];
	char status[MAX_BUF_LENGTH];
	Buffer file_buffer;
	long file_size;
	
	char md5[MD5_DIGEST_LENGTH+1];

	if (check_sum) {
		sprintf(buf, "GETC %s\n", get_name);
	}
	else {
		sprintf(buf, "GET %s\n", get_name);
	}
	
	size_t bytes_sent = write(fd, buf, sizeof(buf));

	size_t bytes_received = get_line(fd, buf, sizeof(buf));

	char *space_pos = strchr(buf, ' ');
	int header_len = space_pos - buf;
	strncpy(status, buf, header_len);
	status[header_len] = '\0';

	if (strcmp(status, "OK") == 0 || strcmp(status, "OKC") == 0) {
		//printf("GET file name : %s\n", get_name);

		bytes_received = get_line(fd, buf, sizeof(buf));
		file_size = atol(buf);
		//printf("file size: %lu\n", file_size);

		if (check_sum) {
			bytes_received = get_line(fd, buf, sizeof(buf));
			strncpy(md5, buf, MD5_DIGEST_LENGTH+1);
			print_md5((unsigned char*)md5);
		}

		int bytes_to_receive = file_size;
		while (bytes_to_receive > 0) {
			bytes_received = read(fd, buf, MAX_BUF_LENGTH);

			if (bytes_received == -1) {
				die("Read Error: ", strerror(errno));
			}

			bytes_to_receive -= bytes_received;
			file_buffer.append(buf, bytes_received);
		}

		if (check_sum && check_md5((unsigned char*)file_buffer.get_c_str(), file_size, (unsigned char*)md5) < 0) {
			die("Checksum Error: ", "check sum mismatch");
		}

		//printf("Received bytes: %d\n", file_buffer->bytes_used);

		write_file(file_buffer.get_c_str(), file_size, save_name);
		printf("File %s saved\n", save_name);
	}
	else {
		printf("Response: %s\n", buf);
	}
}

/*
 * main() - parse command line, open a socket, transfer a file
 */
int run(int argc, char **argv)
{
	/* for getopt */
	long  opt;
	char *server = NULL;
	char *put_name = NULL;
	char *get_name = NULL;
	int   port = 9000;
	char *save_name = NULL;
	int   check_sum = 0;

	check_team(argv[0]);

	/* parse the command-line options. */
	while((opt = getopt(argc, argv, "hs:P:G:S:p::c")) != -1)
	{
		switch(opt)
		{
		case 'h': 
			help(argv[0]); 
			exit(0);
			break;
		case 's': server = optarg; break;
		case 'P': put_name = optarg; break;
		case 'G': get_name = optarg; break;
		case 'S': save_name = optarg; break;
		case 'p': port = atoi(optarg); break;
		case 'c': check_sum = 1;
		}
	}

	/* open a connection to the server */
	int fd = connect_to_server(server, port);

	/* put or get, as appropriate */
	if(put_name)
	{
		put_file(fd, put_name, check_sum);
	}
	else
	{
		get_file(fd, get_name, save_name, check_sum);
	}

	/* close the socket */
	int rc;
	if((rc = close(fd)) < 0)
	{
		die("Close error: ", strerror(errno));
	}
	exit(0);
}

int main(int argc, char **argv)
{
	run(argc, argv);
	/* char *buf;
	int file_len = read_file("myfile.txt", &buf);

	printf("msg len: %d\n", file_len);
	printf("msg:\n%s\n", buf);

	unsigned char *aes_key;
	unsigned char *aes_iv;

	open_key_file(&aes_key, &aes_iv);

	if (aes_key == NULL || aes_iv == NULL) {
		printf("no key file found, generating a new pair of key...\n");
		gen_key(&aes_key, &aes_iv);
	}

	char *enc_msg;

	int enc_msg_len = EVP_encrypt((unsigned char*)buf, file_len, (unsigned char**)&enc_msg, aes_key, aes_iv);

	printf("msg len: %d\n", enc_msg_len);

	printf("encrypted msg:\n%s\n", enc_msg);
	
	write_buffer_to_file(enc_msg, enc_msg_len, "myfile.enc");



	char *enc_msg_read;
	int enc_msg_len_read = read_file("myfile.enc", &enc_msg_read);

	char *dec_msg;
	int dec_msg_len = EVP_decrypt((unsigned char*)enc_msg_read, enc_msg_len_read, (unsigned char**)&dec_msg, aes_key, aes_iv);


	printf("decrypted msg:\n%s\n", dec_msg); */

    
}
