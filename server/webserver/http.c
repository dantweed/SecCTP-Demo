/* Feel free to use this example code in any way
   you see fit (Public Domain) */

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <limits.h>
#include <ctype.h>
#include <microhttpd.h>

#include "../server.h"
#include <mqueue.h>

#define ERROR_PAGE "<html><head><title>Error</title></head><body>Error</body></html>"
#define WORKING "<html><head><title>Processing</title></head><body>Processing request...</body></html>"

static int generate_page (void *cls,
   struct MHD_Connection *connection,
   const char *url,
   const char *method,
   const char *version,
   const char *upload_data,
   size_t *upload_data_size, void **ptr);

static struct MHD_Response *error_response;
static struct MHD_Response *working_response;
static volatile int resume = 0;

mqd_t mq;

int main (int argc, char **argv) {
	struct MHD_Daemon *daemon;	
	
	if (argc != 2) {
		printf("Usage: %s <port> <queue_name> \n",argv[0]);
		return EXIT_FAILURE;
	} 
	
	if ( (mq = mq_open(argv[2], O_RDWR)) == (mqd_t) -1) 
		on_error("queue does not exist");
			
	int port = atoi(argv[1]);
		
	
	error_response = 
		MHD_create_response_from_buffer (strlen (ERROR_PAGE),(void *) ERROR_PAGE, MHD_RESPMEM_PERSISTENT); 
	error_response = 
		MHD_create_response_from_buffer (strlen (WORKING),(void *) WORKING, MHD_RESPMEM_PERSISTENT);  

	daemon = MHD_start_daemon (MHD_USE_SELECT_INTERNALLY, port, NULL, 
					NULL, &generate_page, NULL, MHD_OPTION_END);

	if (NULL == daemon)
		return 1;
	printf("Press any key to shutdown server.\n");
	(void) getchar();
	MHD_stop_daemon (daemon);
	return EXIT_SUCCESS	;
}

static int generate_page (void *cls,
   struct MHD_Connection *connection,
   const char *url,
   const char *method,
   const char *version,
   const char *upload_data,
   size_t *upload_data_size, void **ptr) {
	   
	   
	struct MHD_Response *response;
	int ret;
	int fd;
	struct stat buf;
	
	int m = 0;
	int bytes_rcvd;
	char buffer[MAX_SIZE];
	
	if ( (0 != strcmp (method, MHD_HTTP_METHOD_GET)) &&  
		(0 != strcmp (method, MHD_HTTP_METHOD_HEAD)) )
			return MHD_queue_response (connection, 	
					MHD_HTTP_BAD_REQUEST, error_response);

	fd = -1;
	if (0 != strcmp (url, "/"))     { 
		if ( (NULL == strstr (&url[1], "..")) && ('/' != url[1]) ) {
			fd = open (&url[1], O_RDONLY);			
			m = 0;
		}
	}
	else {
		fd = open ("pages/main.html", O_RDONLY);	
		m = 1;	
	}
	if ( (-1 != fd) && ( (0 != fstat (fd, &buf)) || 
		(! S_ISREG (buf.st_mode)) ) )	{
		(void) close (fd);
		fd = -1;
	}
	
	if (-1 == fd )
		return MHD_queue_response 
				(connection, 	MHD_HTTP_BAD_REQUEST, error_response);

	else if (NULL == (response = MHD_create_response_from_fd (buf.st_size, fd))) 	{
	/* internal error (i.e. out of memory) */
		(void) close (fd);
		return MHD_queue_response (connection, 	MHD_HTTP_BAD_REQUEST, error_response);
	}
	if (m)
		ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	else {				
		ret = MHD_queue_response (connection, MHD_HTTP_PROCESSING, working_response);
		bytes_rcvd = mq_receive(mq, buffer, MAX_SIZE-1, NULL);
		buffer[bytes_rcvd] = '\0';
		if (strncmp(buffer, AUTHORIZED, strlen(AUTHORIZED))) 
			ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
		else
			ret = MHD_queue_response (connection, MHD_HTTP_FORBIDDEN, response);
	}
	MHD_destroy_response (response);
	return ret;
}



