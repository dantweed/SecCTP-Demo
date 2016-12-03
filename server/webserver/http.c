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
#include <signal.h>
#include <errno.h>

//#define DEBUG

#define ERROR_PAGE "<html><head><title>Error</title></head><body>Error</body></html>"
#define UNAUTH "<html><head><title>Unauthorized</title></head><body>Invalid credentials supplied</body></html>"
#define WORKING "<html><head><title>Processing</title></head><body>Processing request...</body></html>"

#define HOSTNAME "localhost"

void sigTermHandler(int sig);
void sigQueueHandler(int sig, siginfo_t *info, void *drop);

static int generate_page (void *cls,
   struct MHD_Connection *connection,
   const char *url,
   const char *method,
   const char *version,
   const char *upload_data,
   size_t *upload_data_size, void **ptr);
   
static struct MHD_Response *error_response;
static struct MHD_Response *working_response;
static struct MHD_Response *forbidden_response;
static volatile int resume = 0;
static volatile int forever = 1;
static volatile int data = 0;
mqd_t mq_rcv;
mqd_t mq_snd; //For use later in server initiated transactions


static int suspend = 0;	

int main (int argc, char **argv) {
	struct MHD_Daemon *daemon;	
	
	if (argc != 4) {
		printf("Usage: %s <webport> <send mqueue name> <recv mqueue name> \n",argv[0]);
		return EXIT_FAILURE;
	} 
			
	if ( (mq_rcv = mq_open(argv[2], O_RDONLY)) == (mqd_t) -1 || (mq_snd = mq_open(argv[3], O_WRONLY)) == (mqd_t) -1) 
		on_error("queue does not exist");
		
	int webport = atoi(argv[1]);
		
	struct sigaction actTerm, actQueue;
	memset(&actTerm, 0, sizeof(actTerm));
	actTerm.sa_handler = &sigTermHandler;	
	
	memset(&actQueue, 0, sizeof(actQueue));
	actQueue.sa_flags = SA_SIGINFO;
	actQueue.sa_sigaction = &sigQueueHandler;	
	
	
	if ( ( sigaction(SIGTERM, &actTerm, NULL)) < 0)
		on_error("Error handling SIGTERM signal");	
	if ( ( sigaction(SIGUSR2, &actQueue, NULL)) < 0)
		on_error("Error handling SIGUSR1 signal");		
			
	error_response = 
		MHD_create_response_from_buffer (strlen (ERROR_PAGE),(void *) ERROR_PAGE, MHD_RESPMEM_PERSISTENT); 
	working_response = 
		MHD_create_response_from_buffer (strlen (WORKING),(void *) WORKING, MHD_RESPMEM_PERSISTENT);  
	forbidden_response =
		MHD_create_response_from_buffer (strlen (UNAUTH),(void *) UNAUTH, MHD_RESPMEM_PERSISTENT);  
	if (MHD_add_response_header(working_response, "SecCTP", DEFAULT_SECCTP_PORT) == MHD_NO) 
				on_error("error adding header");
	
	daemon = MHD_start_daemon (MHD_USE_SELECT_INTERNALLY|MHD_USE_SUSPEND_RESUME|MHD_USE_DEBUG, webport, NULL, 
					NULL, &generate_page, NULL,  MHD_OPTION_END);

	if (NULL == daemon)
		on_error("Error starting daemon");	
	while(forever && daemon);
	
	if (daemon) MHD_stop_daemon (daemon);	
	
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
	
	int main = 0;		
	
	if ( (0 != strcmp (method, MHD_HTTP_METHOD_GET)) &&  
		(0 != strcmp (method, MHD_HTTP_METHOD_HEAD)) ) 			
			return MHD_queue_response (connection, 	
					MHD_HTTP_BAD_REQUEST, error_response);

	fd = -1;
	if (0 != strcmp (url, "/"))     { 
		if ( (NULL == strstr (&url[1], "..")) && ('/' != url[1]) ) {
			fd = open (&url[1], O_RDONLY);
			fd = 1;					
			main = 0;
		}		
	}
	else {
		fd = open ("pages/main.html", O_RDONLY);	
		main = 1;
	}
	
	if ( (-1 != fd) && ( (0 != fstat (fd, &buf)) || 
		(! S_ISREG (buf.st_mode)) ) )	{
		(void) close (fd);
		fd = -1;
	} 
	if (main && -1 == fd ) 
		return MHD_queue_response 
				(connection, 	MHD_HTTP_BAD_REQUEST, error_response);

	else if (main && NULL != (response = MHD_create_response_from_fd (buf.st_size, fd))){
	
		ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
		MHD_destroy_response (response);		
	}
	else if (!main && !suspend){	
		suspend = 1;			
		debug_message("queuing 102 resp\n");
		
		char *location = (char*) calloc(MAX_SIZE, sizeof(char));
		sprintf(location, "%s/%s", HOSTNAME, url);
		
		if (MHD_add_response_header(working_response, "Location", url) == MHD_NO) 
			on_error("error adding header");
		if (MHD_queue_response (connection, MHD_HTTP_SEE_OTHER, working_response)== MHD_NO)
			on_error("error queueing 303 with header");
		debug_message("Re-direct for auth resp queued, waiting for auth\n");
		close(fd);
	}
	else if (suspend && (NULL != (response = MHD_create_response_from_fd (buf.st_size, fd))) ) {
		
		struct stat buf;
		char buffer[MAX_SIZE+1];	
		int bytes_rcvd;	
		
		//Wait on server auth
		if ( (bytes_rcvd = mq_receive(mq_rcv, buffer, MAX_SIZE, NULL) ) < 0) 
			on_error("Queue error %d",errno);fflush(stderr);
			
		buffer[bytes_rcvd] = '\0';
		debug_message("Queue msg: %s$ \n",buffer);
		if (strncmp(buffer, AUTHORIZED, strlen(AUTHORIZED)) == 0 ) {
			if ( MHD_queue_response (connection, MHD_HTTP_OK, response) == MHD_NO) 
				on_error("Error in queue auth resp\n");
		} else {			
			if ( MHD_queue_response (connection, MHD_HTTP_FORBIDDEN, forbidden_response) == MHD_NO) 
				on_error("Error in queue not resp\n")
		}			
		MHD_destroy_response(response);
			
	}
	else {
		/* internal error */
		(void) close (fd);
		return MHD_queue_response (connection, 	MHD_HTTP_INTERNAL_SERVER_ERROR, error_response);
		debug_message("Internal server error");
	}	
	
	return ret;
}

void sigTermHandler(int sig) {	
	forever = 0;
}

void sigQueueHandler(int sig, siginfo_t *info, void *drop) {	
	suspend = 0;	
}

