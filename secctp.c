/* SecCTP support library */ 
#include "secctp.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Helper function for SecCTP messages
 * Builds standard message from status lines
 * Returns 0 on success, -1 indicates some fields invalid
 * (Reference SecCTP draft Sec. 7 )
*/

int generateMsg(char *msg, char *headers, char *body) {
	int ret = -1;
	if (msg && headers) {		
		strcat(msg, headers);
		strcat(msg, "\r\n"); //mandatory blank line
		if (body)
			strcat(msg, body);
		ret = 0;
	}
	return ret;
}


/* Generate SecCTP Hello message
 * Returns 0 on success, -1 indicates some fields invalid
 * (Reference SecCTP draft Sec. 7.1 )
*/
int generateHello(char *msg, char *method, char *user_headers, char *body){
	int ret = -1;
	char *headers = (char*)malloc(MAX_HEADER_SIZE);
//Hello messages require date and accepted languages header fields
	if (headers) {			
		time_t now = time(0);
		struct tm tm = *gmtime(&now);
   		strftime(headers,MAX_HEADER_SIZE,"Date: %a, %d %b %Y %H:%M:%S %Z\r\n", &tm);
		strcat(headers, lang);
		if (user_headers) {
			strcat(headers,user_headers);  //Not robust against overflow yet
		} 	
		if (msg && method) {
			sprintf(msg, "%s %s\r\n", method, VERSION);
			ret = generateMsg(msg, headers, body);
		}
	}
	return ret;
}


/* Generate SecCTP Request message
 * Returns 0 on success, -1 indicates some fields invalid
 * (Reference SecCTP draft Sec. 7.2 )
*/
int generateReq(char *msg, char *method, char *uri,char *headers, char *body){
	int ret = -1;
	if (msg && method && uri && headers) {
		sprintf(msg, "%s %s %s\r\n", method, uri, VERSION);
		ret = generateMsg(msg, headers, body);
	}
	return ret;
}

/* Generate SecCTP Response message
 * Returns 0 on success, -1 indicates some fields invalid
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

