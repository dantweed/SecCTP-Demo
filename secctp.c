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
		char *time = malloc(strlen(DATE_FORMAT));
   		strftime(time,MAX_HEADER_SIZE,DATE_FORMAT, &tm);		
		strcat(msg, time);
		strcat(msg, headers);
		strcat(msg, "\r\n"); //mandatory blank line
		if (body)
			strcat(msg, body);
		ret = 0;
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
int generateReq(char *msg, char *method, char *uri, char *headers, char *body){
	int ret = -1;
	if (msg && method && uri && headers) {
		sprintf(msg, "%s %s %s\r\n", method, uri, VERSION);
		ret = generateMsg(msg, headers, body);
	}
	return ret;
}

/* Generate SecCTP Response message
 * Returns 0 on success, -1 indicates some fields invalid
 * Parameter msg contains formatted message
 * (Reference SecCTP draft Sec. 7.3 )
*/
int generateResp(char *msg, int status_code,char *headers, char *body){
	int ret = -1;
	if (msg && headers) {
		if (check_code(status_code)) {
			sprintf(msg, "%s %d\r\n", VERSION, status_code);
			ret = generateMsg(msg, headers, body);
		}
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
	char *headers;
	int count; 
	
	if (msg != NULL) { /* else msg is not a valid pointer */
		/* extract info line */
		tok = strtok(msg, "\r\n");
		if (tok != NULL) { /* else message is empty*/
			infoline = tok;
			
			/*extract headers */
			tok = strtok(NULL, "\r\n");
			if (tok != NULL) { /* else message is invalid */
				headers = (char*) calloc(MAX_HEADER_SIZE, sizeof(char));
				headers = tok;		
				while (tok != NULL && count <= MAX_HEADER_SIZE - 1) {
					strcat(headers, tok);
					count += strlen(tok);
					tok = strtok(NULL, "\r\n");
				}
				contents->headers = headers;
				/* extract body if exists, otherwise will set to NULL */
				contents->body = strtok(NULL, "\r\n");
			
				/* parse info line */				
				char *toks[3];			
				count = 0;	
				while ( (tok = strtok(infoline, " ")) != NULL && count < 3)
					toks[count++] = tok;
				if (count == 3) { //Request
					contents->type = REQ;
					contents->method = toks[0];
					contents->resource = toks[1];
					contents->version = toks[2];
					ret = 0;
				} else if (count == 2) { //Info or Response
					if (strlen(toks[0]) == strlen(VERSION) && strlen(toks[1]) == 3) { //Matches format for Repsonse
						contents->type = RESP;
						contents->version = toks[0];
						char *end_ptr; 
						int code = strtol(toks[1], &end_ptr, 10);
						if ( errno != ERANGE && errno != 0 && end_ptr == '\0' )  //Number and only a number was found
							contents->status = code;
						if check_code(code) /* if valid, set return flag */
							ret = 0;						
					} else if (strlen(toks[1]) == strlen(VERSION) && strlen(toks[1]) == 3) { //Matches format for hello
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
