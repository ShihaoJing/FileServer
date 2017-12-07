#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/md5.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <thread>
#include <unordered_map>
#include <mutex>
#include "util.h"
#include "support.h"
#include "Server.h"
#include "buffer.h"
#include "LRU.h"

#define MAX_BUF_LENGTH 1024

using namespace std;

int check_request_header(char *buf, char *method, char *file_name) {

    // minimum length of request header is 5.
    if (strlen(buf) < 5) {
        return -1;
    }

    char *space_pos = strchr(buf, ' ');
    if (space_pos == NULL) {
        return -1;
	}
	
	int method_len = space_pos - buf;
    strncpy(method, buf, method_len);
    method[method_len] = '\0';

	if (strcmp(method, "PUT") != 0 && strcmp(method, "GET") != 0 
		&& strcmp(method, "PUTC") != 0 && strcmp(method, "GETC") != 0) {
        return -1;
	}

	if (method_len + 1 == strlen(buf)) { 
		return -1;
	}

	strcpy(file_name, buf + method_len + 1);
	
	return 1;
}

void bad_request(int fd, int err, const char *msg) {
	char buf[1024];

	sprintf(buf, "ERROR %d: %s\n", err, msg);
	send(fd, buf, sizeof(buf), 0);
}

void success_request(int fd, const char *msg) {
	char buf[1024];

	sprintf(buf, "%s\n", msg);
	send(fd, buf, sizeof(buf), 0);
}

void do_PUT(int fd, const char *file_name, int check_sum, LRUCache &lru) {
	size_t bytes_received;
	char buf[MAX_BUF_LENGTH];
	char md5[MD5_DIGEST_LENGTH+1];

	long file_size;
	std::shared_ptr<Buffer> file_buffer = std::make_shared<Buffer>();

	// bytes to receive
	bytes_received = get_line(fd, buf, sizeof(buf));
	file_size = atol(buf);
	if (file_size == 0) {
		bad_request(fd, 1, "invalid file size");
		return;
	}
	//printf("file size: %lu\n", file_size);

	// md5
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
		file_buffer->append(buf, bytes_received);
	}

	lru.put(file_name, file_buffer);

	printf("cached has %d items\n", lru.count());

	if (check_sum && check_md5((unsigned char*)file_buffer->get_c_str(), file_size, (unsigned char*)md5) < 0) {
		bad_request(fd, 6, "md5 check failed");
		return;
	}

	//printf("Received bytes: %d\n", file_buffer->bytes_used);

	write_file(file_buffer->get_c_str(), file_buffer->size(), file_name);
	printf("File: %s saved\n", file_name);
	
	if (check_sum) {
		success_request(fd, "OKC");
	}
	else {
		success_request(fd, "OK");
	}
}

void do_GET(int fd, const char *file_name, int check_sum, LRUCache &lru) {

	Buffer response_buffer;
	long file_size;
	char md5[MD5_DIGEST_LENGTH+1];

	std::shared_ptr<Buffer> file_buffer = lru.get(file_name);

	if (file_buffer == nullptr) {
		printf("Cache Miss\n");

		file_buffer = std::make_shared<Buffer>();

		char *buffer;

		file_size = read_file(file_name, &buffer);

		if (file_size == 0) {
			bad_request(fd, 1, "file doesn't exit");
			return;
		}

		file_buffer->append(buffer, file_size);
		free(buffer);

		lru.put(file_name, file_buffer);
	}
	else {
		printf("Cache Hit\n");
		file_size = file_buffer->size();
	}

	generate_md5((const unsigned char*)file_buffer->get_c_str(), file_size, (unsigned char*)md5);
	print_md5((unsigned char*)md5);

	if (check_sum) {
		response_buffer.appendf("OKC %s\n", file_name);
	}
	else {
		response_buffer.appendf("OKC %s\n", file_name);
	}

	response_buffer.appendf("%lu\n", file_size);

	if (check_sum) {
		response_buffer.appendf("%s\n", md5);
	}
	
	response_buffer.append(file_buffer->get_c_str(), file_size);
	
	const char *response = response_buffer.get_c_str();

	/* send request to the server, handling short counts */
	size_t total_bytes      = response_buffer.size();
	size_t bytes_to_send    = total_bytes;
	size_t bytes_sent       = 0;
	
	while(bytes_to_send > 0)
	{
		if((bytes_sent = write(fd, response, bytes_to_send)) <= 0)
		{
			die("write Error: ", strerror(errno));
			exit(0);
		}
		bytes_to_send -= bytes_sent;
		response += bytes_sent;
	}
}

void help(char *progname)
{
	printf("Usage: %s [OPTIONS]\n", progname);
	printf("Initiate a network file server\n");
	printf("  -m    enable multithreading mode\n");
	printf("  -l    number of entries in the LRU cache\n");
	printf("  -p    port on which to listen for connections\n");
}

void die(const char *msg1, char *msg2)
{
	fprintf(stderr, "%s, %s\n", msg1, msg2);
	exit(0);
}

/*
 * open_server_socket() - Open a listening socket and return its file
 *                        descriptor, or terminate the program
 */
int open_server_socket(int port)
{
	int                listenfd;    /* the server's listening file descriptor */
	struct sockaddr_in addrs;       /* describes which clients we'll accept */
	int                optval = 1;  /* for configuring the socket */

	/* Create a socket descriptor */
	if((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		die("Error creating socket: ", strerror(errno));
	}

	/* Eliminates "Address already in use" error from bind. */
	if(setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int)) < 0)
	{
		die("Error configuring socket: ", strerror(errno));
	}

	/* Listenfd will be an endpoint for all requests to the port from any IP
	   address */
	bzero((char *) &addrs, sizeof(addrs));
	addrs.sin_family = AF_INET;
	addrs.sin_addr.s_addr = htonl(INADDR_ANY);
	addrs.sin_port = htons((unsigned short)port);
	if(bind(listenfd, (struct sockaddr *)&addrs, sizeof(addrs)) < 0)
	{
		die("Error in bind(): ", strerror(errno));
	}

	/* Make it a listening socket ready to accept connection requests */
	if(listen(listenfd, 1024) < 0)  // backlog of 1024
	{
		die("Error in listen(): ", strerror(errno));
	}

	return listenfd;
}

/*
 * handle_requests() - given a listening file descriptor, continually wait
 *                     for a request to come in, and when it arrives, pass it
 *                     to service_function.  Note that this is not a
 *                     multi-threaded server.
 */
void handle_requests(int listenfd, void (*service_function)(int, int), int param, bool multithread)
{
	while(1)
	{
		/* block until we get a connection */
		struct sockaddr_in clientaddr;
		memset(&clientaddr, 0, sizeof(sockaddr_in));
		socklen_t clientlen = sizeof(clientaddr);
		int connfd;
		if((connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen)) < 0)
		{
			die("Error in accept(): ", strerror(errno));
		}

		/* print some info about the connection */
		struct hostent *hp;
		hp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr, sizeof(clientaddr.sin_addr.s_addr), AF_INET);
		if(hp == NULL)
		{
			fprintf(stderr, "DNS error in gethostbyaddr() %d\n", h_errno);
			exit(0);
		}
		char *haddrp = inet_ntoa(clientaddr.sin_addr);
		printf("server connected to %s (%s)\n", hp->h_name, haddrp);

		if (multithread) {
			std::thread t(service_function, connfd, param);
			t.detach();
		}
		else {
			service_function(connfd, param);
			if(close(connfd) < 0)
			{
				die("Error in close(): ", strerror(errno));
			}
			printf("\n");
		}

		/* serve requests */
		//service_function(connfd, param);
		

		/* clean up, await new connection */
		/*
		if(close(connfd) < 0)
		{
			die("Error in close(): ", strerror(errno));
		}
		*/
	}
}
/*
 * file_server() - Read a request from a socket, satisfy the request, and
 *                 then close the connection.
 */
void file_server(int connfd, int lru_size)
{
	/* TODO: set up a few static variables here to manage the LRU cache of
	   files */

	static LRUCache lru(lru_size);
	static unordered_map<string, std::unique_ptr<std::mutex>> locks;
	static mutex map_mutex;
    

	size_t bytes_received;
	char buf[MAX_BUF_LENGTH];

	char method[MAX_BUF_LENGTH];
	char file_name[MAX_BUF_LENGTH];

	// PUT or GET
	bytes_received = get_line(connfd, buf, sizeof(buf));

	if (!check_request_header(buf, method, file_name)) {
		bad_request(connfd, 3, "invalid request");
		return;
	}

	printf("method: %s, filename: %s\n", method, file_name);

	std::mutex *file_mutex;

	{
		std::lock_guard<std::mutex> lock_guard(map_mutex);
		auto it = locks.find(file_name);
		if (it == locks.end()) {
			it = locks.emplace(file_name, std::make_unique<std::mutex>()).first;
		}
		file_mutex = it->second.get();
	}

	std::lock_guard<std::mutex> lock_guard(*file_mutex);

	if (strcmp(method, "PUT") == 0) {
		do_PUT(connfd, file_name, 0, lru);
	}
	else if (strcmp(method, "PUTC") == 0) {
		do_PUT(connfd, file_name, 1, lru);
	}
	else if (strcmp(method, "GET") == 0) {
		do_GET(connfd, file_name, 0, lru);
	}
	else {
		do_GET(connfd, file_name, 1, lru);
	}

	if(close(connfd) < 0)
	{
		die("Error in close(): ", strerror(errno));
	}

	printf("\n");
}

/*
 * main() - parse command line, create a socket, handle requests
 */
int main(int argc, char **argv)
{
	/* for getopt */
	long opt;
	int  lru_size = 3;
	int  port     = 9000;
	bool multithread = false;

	check_team(argv[0]);

	/* parse the command-line options.  They are 'p' for port number,  */
	/* and 'l' for lru cache size, 'm' for multi-threaded.  'h' is also supported. */
	while((opt = getopt(argc, argv, "hml:p:")) != -1)
	{
		switch(opt)
		{
		case 'h': 
			help(argv[0]); 
			exit(0);
			break;
		case 'l': lru_size = atoi(optarg); break;
		case 'm': multithread = true;	break;
		case 'p': port = atoi(optarg); break;
		}
	}

	/* open a socket, and start handling requests */
	int fd = open_server_socket(port);
	handle_requests(fd, file_server, lru_size, multithread);

	exit(0);
}
