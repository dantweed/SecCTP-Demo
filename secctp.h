#ifndef SECCTP_H
#define SECCTP_H

/* Some useful constants */

#ifndef VERSION
	#define VERSION "SecCTP/1.0"
#endif

#ifndef NULL
	#define NULL 0
#endif

#define MAX_SIZE 256

/* Some useful macros */
#define phrase(status_code) (((status_code) == OK) ? "Ok": \
		((status_code) == OTHER) ? "See Other" : \
		((status_code) == BAD) ? "Bad Request" : \
		((status_code) == UNAUTH) ? "Unauthorized" : \
		((status_code) == TIMEOUT) ? "Request Timeout" : \
		((status_code) == SERVER_ERR) ? "Internal Server Error" :\
		((status_code) == NOT_IMPL) ? "Not Implemented" : "Invalid status code")

#define check_code(status_code) (((status_code) == OK) || \
		((status_code) == OTHER)  || \
		((status_code) == BAD) || \
		((status_code) == UNAUTH) || \
		((status_code) == TIMEOUT) || \
		((status_code) == SERVER_ERR) || \
		((status_code) == NOT_IMPL) ? 1 : 0 )

#define eos(s) ((s)+strlen(s))

/* Methods */

#define INFO "INFO"
#define GET "GET"
#define POST "POST"

/* Status Codes */ 

#define OK 200
#define OTHER 303
#define BAD 400
#define UNAUTH 401
#define TIMEOUT 408
#define SERVER_ERR 500
#define NOT_IMPL 501

#endif //#ifndef SECCTP_H

int generateHello(char *msg, char *method,char *headers, char *body);
int generateReq(char *msg, char *method, char *uri,char *headers, char *body); 
int generateResp(char *msg, int status_code,char *headers, char *body);
