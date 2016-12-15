#ifndef SECCTP_H
#define SECCTP_H

/* Some useful constants */

#ifndef VERSION
	#define VERSION "SecCTP/1.0"
#endif

#ifndef NULL
	#define NULL 0
#endif

#define PWD_LENGTH 20
#define UNAME_LENGTH 20
#define MAX_CRED_LENGTH (UNAME_LENGTH+PWD_LENGTH)
#define DEFAULT_CREDS "secctp:pass"
#define AUTH_TAG "Authorization: Basic "

#define MAX_HEADER_SIZE 1024 

#define DATE_FORMAT "Date: %a, %d %b %Y %H:%M:%S %Z\r\n"
#define LANG "Accept-Language: en-gb, en\r\n" //Only accept engligh for now

/* Some macros */
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

typedef enum msgType {HELLO=0,REQ, RESP} msgType;

typedef struct msgContents{
	msgType type; 	
	char * headers;
	char * body;
	char * method;	
	char * version;
	int status;		
	char * resource;	
} msgContents;

int generateHello(char *msg, char *method,char *headers, char *body);
int generateReq(char *msg, char *method, char *uri,char *headers, char *body); 
int generateResp(char *msg, int status_code,char *headers, char *body);

int parseMessage(msgContents *contents, char *msg);
int authorization(char *headers);

#endif //#ifndef SECCTP_H


