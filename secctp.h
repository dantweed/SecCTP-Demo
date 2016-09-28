#ifndef SECCTP_H
#define SECCTP_H

/* Some message macros */

/* Reference SecCTP draft Sec. 7 */
#define secCTP_msg(msg,start_line,header,body) \
	sprintf(msg, "%s\n%s\n%s", start_line, header, body)

/* Reference SecCTP draft Sec. 7.1 */
#define hello(info_line,method,version) \
	sprintf(info_line, "%s %s", method, version)
/* Reference SecCTP draft Sec. 7.2 */
#define request(req_line,method, req_uri,version) \
	sprintf(req_line, "%s %s %s", method, req_uri, version)
/* Reference SecCTP draft Sec. 7.3 */
#define response(status_line,version,status_code) \
	sprintf(status_line, "%s %s", version, status_code)

#define str(s) #s

/* Some useful constants */

#ifndef VERSION
	#define VERSION "SecCTP/1.0"
#endif

/* methods */

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

#define phrase(status_code) (((status_code) == OK) ? "Ok": \
		((status_code) == OTHER) ? "See Other" : \
		((status_code) == BAD) ? "Bad Request" : \
		((status_code) == UNAUTH) ? "Unauthorized" : \
		((status_code) == TIMEOUT) ? "Request Timeout" : \
		((status_code) == SERVER_ERR) ? "Internal Server Error" :\
		((status_code) == NOT_IMPL) ? "Not Implemented" : "Invalid status code")

#endif //#ifndef SECCTP_H
