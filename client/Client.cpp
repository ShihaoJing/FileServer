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
 * echo_client() - this is dummy code to show how to read and write on a
 *                 socket when there can be short counts.  The code
 *                 implements an "echo" client.
 */
void echo_client(int fd)
{
	// main loop
	while(1)
	{
		/* set up a buffer, clear it, and read keyboard input */
		const int MAXLINE = 8192;
		char buf[MAXLINE];
		bzero(buf, MAXLINE);
		if(fgets(buf, MAXLINE, stdin) == NULL)
		{
			if(ferror(stdin))
			{
				die("fgets error", strerror(errno));
			}
			break;
		}

		/* send keystrokes to the server, handling short counts */
		size_t n = strlen(buf);
		size_t nremain = n;
		ssize_t nsofar;
		char *bufp = buf;
		while(nremain > 0)
		{
			if((nsofar = write(fd, bufp, nremain)) <= 0)
			{
				if(errno != EINTR)
				{
					fprintf(stderr, "Write error: %s\n", strerror(errno));
					exit(0);
				}
				nsofar = 0;
			}
			nremain -= nsofar;
			bufp += nsofar;
		}

		/* read input back from socket (again, handle short counts)*/
		bzero(buf, MAXLINE);
		bufp = buf;
		nremain = MAXLINE;
		while(1)
		{
			if((nsofar = read(fd, bufp, nremain)) < 0)
			{
				if(errno != EINTR)
				{
					die("read error: ", strerror(errno));
				}
				continue;
			}
			/* in echo, server should never EOF */
			if(nsofar == 0)
			{
				die("Server error: ", "received EOF");
			}
			bufp += nsofar;
			nremain -= nsofar;
			if(*(bufp-1) == '\n')
			{
				*bufp = 0;
				break;
			}
		}

		/* output the result */
		printf("%s", buf);
	}
}

/*
 * put_file() - send a file to the server accessible via the given socket fd
 */
void put_file(int fd, char *put_name, int check_sum)
{
	/* TODO: implement a proper solution, instead of calling the echo() client */

	/* Open file, get size of file, and read content of file into a buffer*/

	Buffer *request_buffer = buffer_alloc(DEFAULT_BUFFER_SIZE);

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

	unsigned char *md5 = generate_md5(buffer, file_size);

	if (check_sum) {
		buffer_appendf(request_buffer, "PUTC %s\n", put_name);
	}
	else {
		buffer_appendf(request_buffer, "PUT %s\n", put_name);
	}
	
	buffer_appendf(request_buffer, "%lu\n", file_size);

	if (check_sum) {
		buffer_appendf(request_buffer, "%s\n", md5);
		print_md5(md5);
	}

	buffer_appendf(request_buffer, "%s", buffer);

	free(md5);
	free(buffer);
	
	char *request = request_buffer->contents;

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


	buffer_free(request_buffer);

	//printf("client send %lu bytes to server\n", total_bytes);

	/* get response from server */

	char read_buffer[DEFAULT_BUFFER_SIZE];
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
	char buf[DEFAULT_BUFFER_SIZE];
	char status[DEFAULT_BUFFER_SIZE];
	Buffer *file_buffer;
	long file_size;
	size_t bytes_sent;
	char md5[MD5_DIGEST_LENGTH+1];

	if (check_sum) {
		sprintf(buf, "GETC %s\n", get_name);
	}
	else {
		sprintf(buf, "GET %s\n", get_name);
	}
	
	bytes_sent = write(fd, buf, sizeof(buf));

	size_t bytes_received = get_line(fd, buf, sizeof(buf));

	char *space_pos = strchr(buf, ' ');
	int header_len = space_pos - buf;
	strncpy(status, buf, header_len);
	status[header_len] = '\0';

	if (strcmp(status, "OK") == 0 || strcmp(status, "OKC") == 0) {
		//printf("GET file name : %s\n", get_name);

		bytes_received = get_line(fd, buf, sizeof(buf));
		file_size = atol(buf);
		file_buffer = buffer_alloc(file_size);
		//printf("file size: %lu\n", file_size);

		if (check_sum) {
			bytes_received = get_line(fd, buf, sizeof(buf));
			strncpy(md5, buf, MD5_DIGEST_LENGTH+1);
			print_md5((unsigned char*)md5);
		}

		int bytes_to_receive = file_size;
		while (bytes_to_receive > 0) {
			bytes_received = read(fd, buf, DEFAULT_BUFFER_SIZE);

			if (bytes_received == -1) {
				die("Read Error: ", strerror(errno));
			}

			bytes_to_receive -= bytes_received;
			buffer_append(file_buffer, buf, bytes_received);
		}

		if (check_sum && check_md5((unsigned char*)file_buffer->contents, file_size, (unsigned char*)md5) < 0) {
			die("Checksum Error: ", "check sum mismatch");
			buffer_free(file_buffer);
			return;
		}

		//printf("Received bytes: %d\n", file_buffer->bytes_used);

		if(write_buffer_to_file(file_buffer->contents, file_buffer->bytes_used, save_name) < 0) {
			printf("Error %s\n", "Failed to write to file");
		}
		else {
			printf("File %s saved\n", save_name);
		}

		buffer_free(file_buffer);
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

int main()
{
	char *buf = read_file("myfile.txt");
	printf("msg:\n%s\n", buf);

	unsigned char *aes_key;
	unsigned char *aes_iv;

	open_key_file(&aes_key, &aes_iv);

	if (aes_key == NULL || aes_iv == NULL) {
		printf("no key file found, generating a new pair of key...\n");
		gen_key(&aes_key, &aes_iv);
	}

	EVP_encrypt((unsigned char*)buf, strlen(buf) + 1, aes_key, aes_iv);
}
