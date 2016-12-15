/* SecCTP support library */ 
#include "secctp.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>

/* Helper function for SecCTP messages
 * Builds standard message from status lines
 * Returns 0 on success, -1 indicates some fields invalid
 * (Reference SecCTP draft Sec. 7 )
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
		strcat(msg, headers);
		strcat(msg, "\r\n"); //mandatory blank line
		if (body)
			strcat(msg, body);
		ret = strlen(msg);
		free(time);
	}	
	return ret;
}


/* Generate SecCTP Hello message
 * Returns 0 on success, -1 indicates some fields invalid
 * Parameter msg contains formatted message
 * (Reference SecCTP draft Sec. 7.1 )
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
			sprintf(msg, "%s %s\r\n", method, VERSION);
			ret = generateMsg(msg, headers, body);
		}
		free(headers);
	}
	return ret;
}


/* Generate SecCTP Request message
 * Returns 0 on success, -1 indicates some fields invalid
 * Parameter msg contains formatted message
 * (Reference SecCTP draft Sec. 7.2 )
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
			sprintf(msg, "%s %s %s\r\n", method, uri, VERSION);
			ret = generateMsg(msg, headers, body);
		}
		free(headers);
	}
	return ret;	
}

/* Generate SecCTP Response message
 * Returns 0 on success, -1 indicates some fields invalid
 * Parameter msg contains formatted message
 * (Reference SecCTP draft Sec. 7.3 )
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
			sprintf(msg, "%s %d\r\n", VERSION, status_code);
			ret = generateMsg(msg, headers, body);
		}
		free(headers);
	}
	return ret;	
}

/* Extract contents of SecCTP message
 * Returns 0 on success, -1 indicates some fields invalid
 * Parameter contents contains the results
 * (Reference SecCTP draft Sec. 7,7.1-3 )
*/
int parseMessage(msgContents *contents, char *msg) {
	int ret = -1;
	char *tok;
	char *infoline;	
	int count = 0; 	
	
	if (msg != NULL) { /* else msg is not a valid pointer */
		/* extract info line */
		tok = strtok(msg, "\r\n");
		if (tok != NULL) { /* else message is empty*/
			infoline = tok;
			
			/*extract headers */
			tok = strtok(NULL, "\r\n");
			if (tok != NULL) { /* else message is invalid */
				if (contents->headers != NULL)
					contents->headers[0] = '\0';
				else 
					contents->headers = (char*) calloc(MAX_HEADER_SIZE, sizeof(char));
					
				while (tok != NULL && count <= MAX_HEADER_SIZE - 1) {
					strncat(contents->headers, tok, strlen(tok));
					strncat(contents->headers, "\r\n", 2);
					count += strlen(tok);
					tok = strtok(NULL, "\r\n");
				}
				
				/* extract body if exists, otherwise will set to NULL */
				contents->body = strtok(NULL, "\r\n");
			
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
	
	if (headers) { //TODO:  Change to authentication against list/dbase of credentials
		if (sscanf(strstr(headers, AUTH_TAG)+strlen(AUTH_TAG) ,"%s\r\n%*s",creds) > 0
				&& strlen(DEFAULT_CREDS) == strlen(creds) ) {
			ret = (strncmp(DEFAULT_CREDS, creds, strlen(DEFAULT_CREDS)) == 0);				
		}			
	}	
	return ret;
}
