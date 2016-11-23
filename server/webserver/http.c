/* Feel free to use this example code in any way
   you see fit (Public Domain) */

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <string.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <limits.h>
#include <ctype.h>
#include <microhttpd.h>

#define PORT 8888
static int generate_page (void *cls,
	       struct MHD_Connection *connection,
	       const char *url,
	       const char *method,
	       const char *version,
	       const char *upload_data,
	       size_t *upload_data_size, void **ptr);

static struct MHD_Response *error_response;
#define ERROR_PAGE "<html><head><title>Error</title></head><body>Error</body></html>"

int main ()
{
  struct MHD_Daemon *daemon;
  
  error_response = MHD_create_response_from_buffer (strlen (ERROR_PAGE),(void *) ERROR_PAGE, MHD_RESPMEM_PERSISTENT); 

  daemon = MHD_start_daemon (MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
                             &generate_page, NULL, MHD_OPTION_END);

  if (NULL == daemon)
    return 1;

  (void) getchar ();

  MHD_stop_daemon (daemon);
  return 0;
}

static int generate_page (void *cls,
	       struct MHD_Connection *connection,
	       const char *url,
	       const char *method,
	       const char *version,
	       const char *upload_data,
	       size_t *upload_data_size, void **ptr)
{
  struct MHD_Response *response;
  int ret;
  int fd;
  struct stat buf;

      ssize_t got;
      const char *mime;

	if ( (0 != strcmp (method, MHD_HTTP_METHOD_GET)) &&  (0 != strcmp (method, MHD_HTTP_METHOD_HEAD)) )
		return MHD_queue_response (connection, 	MHD_HTTP_BAD_REQUEST, error_response);
		
	fd = -1;
	if (0 != strcmp (url, "/"))     { 
		if ( (NULL == strstr (&url[1], "..")) && ('/' != url[1]) ) {
			fd = open (&url[1], O_RDONLY);			
		}
	}
	else {
		fd = open ("pages/main.html", O_RDONLY);		
	}
	if ( (-1 != fd) && ( (0 != fstat (fd, &buf)) || (! S_ISREG (buf.st_mode)) ) )
	{
		(void) close (fd);
		fd = -1;

	}
	if (-1 == fd )
		return MHD_queue_response (connection, 	MHD_HTTP_BAD_REQUEST, error_response);

	else if (NULL == (response = MHD_create_response_from_fd (buf.st_size, fd)))
	{
		/* internal error (i.e. out of memory) */
		(void) close (fd);
		return MHD_queue_response (connection, 	MHD_HTTP_BAD_REQUEST, error_response);
		
	}

	
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_destroy_response (response);
	return ret;
}



