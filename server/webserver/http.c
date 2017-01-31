#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
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

#define ERROR_PAGE "<html><head><title>Error</title></head><body>Error</body></html>"
#define UNAUTH "<html><head><title>Authorization Failure</title></head><body>Invalid credentials supplied</body></html>"
#define WORKING "<html><head><title>Processing</title></head><body>Processing request...</body></html>"
#define  PROCESSED "<html><head><title>Success</title></head><body>Payment submitted successfully</body></html>"

#define POSTBUFFERSIZE  512
#define GET 0
#define POST 1
#define COOKIE_NAME "Session"


struct connection_info_struct {
  int connectiontype;
  char *answerstring;
  struct MHD_PostProcessor *postprocessor;
  int existing;
};

int processAuth(char * msg) ;
void sigTermHandler(int sig);
void sigQueueHandler(int sig, siginfo_t *info, void *drop);
int generateCookie(char *cookie, int size);
static int generate_page (void *cls,
   struct MHD_Connection *connection,
   const char *url,
   const char *method,
   const char *version,
   const char *upload_data,
   size_t *upload_data_size, void **con_ref);

static int iterate_post (void *coninfo_cls, 
	enum MHD_ValueKind kind, const char *key,
	const char *filename, const char *content_type,
	const char *transfer_encoding, const char *data, uint64_t off,
	size_t size);

static void request_completed (void *cls, 
	struct MHD_Connection *connection,
	void **con_cls, enum MHD_RequestTerminationCode toe);

static struct MHD_Response *error_response;
static struct MHD_Response *working_response;
static struct MHD_Response *forbidden_response;
static struct MHD_Response *processed_response;

static volatile int resume = 0;
static volatile int forever = 1;
static volatile int data = 0;

mqd_t mq_rcv;
mqd_t mq_snd; 

int server_pid; 
static int suspend = 0;	

int main (int argc, char **argv) {
	struct MHD_Daemon *daemon;	
	
	if (argc != 5) {
		printf("Usage: %s <webport> <send mqueue name> <recv mqueue name> <server pid> \n",argv[0]);
		return EXIT_FAILURE;
	} 
	server_pid = atoi(argv[4]);
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
	processed_response =
		MHD_create_response_from_buffer (strlen (PROCESSED),(void *) PROCESSED, MHD_RESPMEM_PERSISTENT);  
	if (MHD_add_response_header(working_response, "SecCTP", DEFAULT_SECCTP_PORT) == MHD_NO) 
				on_error("error adding header");
	
	daemon = MHD_start_daemon (MHD_USE_SELECT_INTERNALLY|MHD_USE_SUSPEND_RESUME|MHD_USE_DEBUG, webport, NULL, 
					NULL, &generate_page, NULL, MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,  MHD_OPTION_END);

	if (NULL == daemon)
		on_error("Error starting daemon");	
	while(forever && daemon);
	
	if (daemon) MHD_stop_daemon (daemon);	
	
	return EXIT_SUCCESS	;
}

static void
request_completed (void *cls, struct MHD_Connection *connection,
                   void **con_cls, enum MHD_RequestTerminationCode toe)
{
  struct connection_info_struct *con_info = *con_cls;

  if (NULL == con_info)
    return;

  if (con_info->connectiontype == POST)
    {
      MHD_destroy_post_processor (con_info->postprocessor);
      if (con_info->answerstring)
        free (con_info->answerstring);
    }

  free (con_info);
  *con_cls = NULL;
}

static int generate_page (void *cls, 
   struct MHD_Connection *connection,
   const char *url,
   const char *method,
   const char *version,
   const char *upload_data,
   size_t *upload_data_size, void **con_ref) {	   
	   
	struct MHD_Response *response;
	struct connection_info_struct *con_info;
	int ret;
	int fd;
	struct stat buf;
	
	int main = 0;
	int post = 0;		
	post = (0 == strcmp (method, MHD_HTTP_METHOD_POST));
	if ( (0 != strcmp (method, MHD_HTTP_METHOD_GET)) &&  
			(0 != strcmp (method, MHD_HTTP_METHOD_HEAD)) && 
				(0 != strcmp (method, MHD_HTTP_METHOD_POST)) 	)
				return MHD_queue_response (connection, 	
						MHD_HTTP_BAD_REQUEST, error_response);
	if (NULL == *con_ref)    {
      
      con_info = malloc (sizeof (struct connection_info_struct));
      if (NULL == con_info)
        return MHD_NO;
      con_info->answerstring = NULL; 
      con_info->existing = (NULL != MHD_lookup_connection_value (connection, MHD_COOKIE_KIND, COOKIE_NAME) );
      if ( post  ){
          con_info->postprocessor =
            MHD_create_post_processor (connection, POSTBUFFERSIZE,
                                       iterate_post, (void *) con_info);
          if (NULL == con_info->postprocessor) {
              free (con_info);
              return MHD_NO;
            }

          con_info->connectiontype = POST;
        }
      else
        con_info->connectiontype = GET;

      *con_ref = (void *) con_info;

      return MHD_YES;
    }				
	
	fd = -1;
	if (0 != strcmp (url, "/") && NULL == strstr(&url[1], "favicon.ico"))     { 
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
	debug_message("main = %d -- suspend = %d -- post = %d\n",main,suspend,post);
	if (main && -1 == fd ) 
		return MHD_queue_response 
				(connection, 	MHD_HTTP_BAD_REQUEST, error_response);

	else if (main && NULL != (response = MHD_create_response_from_fd (buf.st_size, fd))){
	
		ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
		MHD_destroy_response (response);		
	}
	else if (!con_info->existing && !main && !suspend && !post){	
		suspend = 1;			

		debug_message("Queuing 303 resp\n");
		
		if (MHD_add_response_header(working_response, "Location", url) == MHD_NO) 
			on_error("Error adding header");
		if ( ( ret = MHD_queue_response (connection, MHD_HTTP_SEE_OTHER, working_response) ) == MHD_NO)
			on_error("Error queueing 303 with header");
		debug_message("Re-direct for auth resp queued, waiting for auth\n");
		close(fd);
	}
	else if (!main && post) {
	
      struct connection_info_struct *con_info = *con_ref;
      if (*upload_data_size != 0)  {
          MHD_post_process (con_info->postprocessor, upload_data,
                            *upload_data_size);
          *upload_data_size = 0; 
          return MHD_YES;
        }
      else if (NULL != con_info->answerstring) {
		struct sockaddr **  addr =	(struct sockaddr **)MHD_get_connection_info (connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
		char msg[MAX_SIZE+1];;
		if ((*addr)->sa_family == AF_INET) {
				struct sockaddr_in *sin = (struct sockaddr_in *) *addr;
				snprintf(msg, MAX_SIZE, "%s:%s", inet_ntoa(sin->sin_addr),con_info->answerstring);
		}
        else {
			on_error("Invalid client address \n");
		}
	
		debug_message("Address = %s\n",msg)																					
	    processAuth(msg);
		if (  (MHD_queue_response (connection, MHD_HTTP_OK, processed_response) == MHD_NO) )  
			on_error("Error in queue resp\n")
		} else {			
			if ( MHD_queue_response (connection, MHD_HTTP_FORBIDDEN, forbidden_response) == MHD_NO) 
				on_error("Error in queue not auth resp\n")
		}	
	
	}
	else if (con_info->existing || ( suspend && (NULL != (response = MHD_create_response_from_fd (buf.st_size, fd)))) ) {
		int auth = 0; 
		char * cookie = NULL;
		if (con_info->existing || (auth  = processAuth(NULL)) ) {
			if (auth) {
				cookie = (char*)calloc(128, sizeof(char));				  
				
				if (cookie && generateCookie(cookie, 128) >= 0 && MHD_YES != MHD_set_connection_value (connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_SET_COOKIE,cookie))
					on_error("Error adding cookie\n");
			}
			if ( MHD_queue_response (connection, MHD_HTTP_OK, response) == MHD_NO) {
				on_error("Error in queue auth resp\n");
			}
			else
				MHD_destroy_response(response);
		} else {			
			if ( MHD_queue_response (connection, MHD_HTTP_FORBIDDEN, forbidden_response) == MHD_NO) 
				on_error("Error in queue not auth resp\n")
		}
		if (cookie) free(cookie);						
	}
	else {
		/* internal error */
		(void) close (fd);
		return MHD_queue_response (connection, 	MHD_HTTP_INTERNAL_SERVER_ERROR, error_response);
		debug_message("Internal server error");
	}	
	debug_message("returning ret = %d\n",ret);	
	return ret;
}





int processAuth(char * msg) {
	
	char buffer[MAX_SIZE+1];	
	int bytes_rcvd, ret;	
	
	if (NULL != msg) { //Server initiated authentication
		ret = mq_send(mq_snd, msg, strlen(msg), 0);						
							
		debug_message("msg sent %d\n", ret);
		if (ret < 0) {  
			on_error("Error in send %d\n", errno); 
		} else {
			union sigval auth;
			auth.sival_int = 1;	
			
			if ( (ret = sigqueue(server_pid, SIGUSR2, auth)) < 0) {
				on_error("error in signal %d\n",errno);
			} else {
				debug_message("signal sent\n");	
			}
		}	
		//return 1; 							
	}
	//Wait on client auth
	if ( (bytes_rcvd = mq_receive(mq_rcv, buffer, MAX_SIZE, NULL) ) < 0) 
		on_error("Queue error %d",errno);

	buffer[bytes_rcvd] = '\0';
	debug_message("Queue msg: %s$ \n",buffer);
	return 	 (strncmp(buffer, AUTHORIZED, strlen(AUTHORIZED)) == 0 );
}


void sigTermHandler(int sig) {	
	forever = 0;
}

void sigQueueHandler(int sig, siginfo_t *info, void *drop) {	
	suspend = 0;	
}

static int
iterate_post (void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
              const char *filename, const char *content_type,
              const char *transfer_encoding, const char *data, uint64_t off,
              size_t size)
{
  struct connection_info_struct *con_info = coninfo_cls;

  if (0 == strcmp (key, "pmtAmt"))
    {
      if ((size > 0) && (size <= 64))
        {
          char *answerstring;
          answerstring = malloc (256);
          if (!answerstring)
            return MHD_NO;

          snprintf (answerstring, 256,  data);
          con_info->answerstring = answerstring;
        }
      else
        con_info->answerstring = NULL;

      return MHD_NO;
    }

  return MHD_YES;
}

int generateCookie(char *cookie, int size) {
	
	char raw[65];
	time_t t;
	
	char bases[3]= {'a','A','0'};
	srand((unsigned)time(&t));
	
	for (int i=0;i<sizeof (raw);i++) {
		char base = bases[rand()%3];
		int mod = (base == 2)? 10: 26;
		raw[i] = base + (rand () % mod); 
	}
	raw[64] = '\0';
	return snprintf (cookie, size, "%s=%s", COOKIE_NAME, raw);

}
