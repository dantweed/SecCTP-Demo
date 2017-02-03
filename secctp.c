/* SecCTP support library */ 
#include "secctp.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

#define DELIM "\r\n" //Message line delimeter for convenience

/** Generate correctly formatted SecCTP message
 * 
 * @param msg 		Pointer to buffer where the resulting message is stored
 * 					which should contain applicable info-line
 * @param headers	Composed message headers (must include default headers
 * @param body		Optional message body
 * 
 * @return Length of formatted message or -1 in case of error
 * Reference SecCTP draft Sec. 7 
*/
int generateMsg(char *msg, char *headers, char *body) {
	//All messages require the date header field
	int ret = -1;
	if (msg && headers) {		
		time_t now = time(0);
		struct tm tm = *gmtime(&now);
		char *time = (char *)calloc(strlen(DATE_FORMAT)+1, sizeof(char));
   		strftime(time,strlen(DATE_FORMAT),DATE_FORMAT, &tm);
		strcat(msg, time);
		strcat(msg,DELIM);
		strcat(msg, headers);
		strcat(msg,DELIM); //mandatory blank line
		if (body)
			strcat(msg, body);
		ret = strlen(msg);
		free(time);
	}	
	return ret;
}


/** Generate correctly formatted SecCTP Hello message
 * 
 * @param msg 			Pointer to buffer where the resulting message is stored
 * @param method		Message method {INFO, GET, POST}
 * @param user_headers	Optional user supplied message headers
 * @param body			Optional message body
 * 
 * @return Length of formatted message or -1 in case of error
 *
 * Reference SecCTP draft Sec. 7.1 
*/
int generateHello(char *msg, char *method, char *user_headers, char *body){
	int ret = -1;
	char *headers = (char*)calloc(MAX_HEADER_SIZE, sizeof(char));
	if (headers != NULL) {
		//Hello messages require accepted languages header field		
		strcat(headers, LANG);
		if (user_headers) {
			strcat(headers,user_headers);  //Not robust against overflow
		} 	
		if (msg && method) {
			sprintf(msg, "%s %s", method, VERSION);
			strcat(msg,DELIM);
			ret = generateMsg(msg, headers, body);
		}
		free(headers);
	}
	return ret;
}


/** Generate correctly formatted SecCTP Request message
 * 
 * @param msg 			Pointer to buffer where the resulting message is stored
 * @param method		Message method {INFO, GET, POST}
 * @param uri			Uniform resource identifier being requested
 * @param user_headers	Optional user supplied message headers
 * @param body			Optional message body
 * 
 * @return Length of formatted message or -1 in case of error
 *
 * Reference SecCTP draft Sec. 7.2 
*/
int generateReq(char *msg, char *method, char *uri, char *user_headers, char *body){
	int ret = -1;
	char *headers = (char*)calloc(MAX_HEADER_SIZE, sizeof(char));
	if (headers != NULL) {
		//Hello messages require accepted languages header field		
		strcat(headers, LANG);
		if (user_headers) {
			strcat(headers,user_headers);  //Not robust against overflow
		} 	
		if (msg && method && uri && headers) {
			sprintf(msg, "%s %s %s", method, uri, VERSION);
			strcat(msg,DELIM);
			ret = generateMsg(msg, headers, body);
		}
		free(headers);
	}
	return ret;	
}

/** Generate correctly formatted SecCTP Response message
 * 
 * @param msg 			Pointer to buffer where the resulting message is stored
 * @param status_code	Response code to applicable request
 * @param user_headers	Optional user supplied message headers
 * @param body			Optional message body
 * 
 * @return Length of formatted message or -1 in case of error
 *
 * Reference SecCTP draft Sec. 7.3 
*/
int generateResp(char *msg, int status_code, char *user_headers, char *body){	
	int ret = -1;
	char *headers = (char*)calloc(MAX_HEADER_SIZE, sizeof(char));
	if (headers != NULL) {
		//Hello messages require accepted languages header field		
		strcat(headers, LANG);
		if (user_headers) {
			strcat(headers,user_headers);  //Not robust against overflow
		} 			
		if (check_code(status_code) && msg && headers) {
			sprintf(msg, "%s %d", VERSION, status_code);
			strcat(msg,DELIM);
			ret = generateMsg(msg, headers, body);
		}
		free(headers);
	}
	return ret;	
}

/** Helper function for parsing SecCTP messages
 * 
 * @param contents 	Pointer to struct where the message contents will be stored
 * @param msg		SecCTP message to be processed
 * 
 * @return 0 for success, -1 in case of error or invalid message
 *
 * Reference SecCTP draft Sec. 7,1-3
*/
int parseMessage(msgContents *contents, char *msg) {
	int ret = -1;
	char *tok;
	char *infoline;	
	int count = 0; 	
	
	if (msg != NULL) { /* else msg is not a valid pointer */
		/* extract info line */
		tok = strtok(msg, DELIM);
		if (tok != NULL) { /* else message is empty*/
			infoline = tok;
			
			/*extract headers */
			tok = strtok(NULL, DELIM);
			if (tok != NULL) { /* else message is invalid */
				if (contents->headers != NULL)
					contents->headers[0] = '\0';
				else 
					contents->headers = (char*) calloc(MAX_HEADER_SIZE, sizeof(char));
					
				while (tok != NULL && count <= MAX_HEADER_SIZE - 1) {					
					strncat(contents->headers, tok, strlen(tok));
					strncat(contents->headers, DELIM, 2);
					count += strlen(tok);
					tok = strtok(NULL, DELIM);					
				}
				
				/* extract body if exists, otherwise will set to NULL */
				contents->body = strtok(NULL, DELIM);
			
				/* parse info line */				
				char *toks[3];			
				count = 0;	
				tok = strtok(infoline, " ");
				while ( tok != NULL && count < 3) {			
					toks[count++] = tok;
					tok = strtok(NULL, " ");
				}
				
				if (count == 3) { //Request
					contents->type = REQ;
					contents->method = toks[0];
					contents->resource = toks[1];
					contents->version = toks[2];
					ret = 0;
				} else if (count == 2) { //Hello or Response
					if (strlen(toks[0]) == strlen(VERSION)) { //Matches format for Repsonse
						contents->type = RESP;
						contents->version = toks[0];
						char *end_ptr; 
						int code = strtol(toks[1], &end_ptr, 10);							
						if check_code(code) {/* if valid, set return flag */
							contents->status = code;
							ret = 0;		
						} 						
					} else if (strlen(toks[1]) == strlen(VERSION)) { //Matches format for hello
						contents->type = HELLO;
						contents->method = toks[0];						
						contents->version = toks[1];
						ret = 0;
					} //Else invalid 
				} // else invalid message 				
			}
		}
	}
	
	return ret;
}

/* For now assume credentials are secctp:pass */
int authorization(char *headers) {
	int ret = 0;
	char creds[MAX_CRED_LENGTH];
	
	if (headers) { //TODO:  Change to authentication against list/dbase/hash of credentials
		if (sscanf(strstr(headers, AUTH_TAG)+strlen(AUTH_TAG) ,"%s\r\n%*s",creds) > 0
				&& strlen(DEFAULT_CREDS) == strlen(creds) ) {
			ret = (strncmp(DEFAULT_CREDS, creds, strlen(DEFAULT_CREDS)) == 0);				
		}			
	}	
	return ret;
}
