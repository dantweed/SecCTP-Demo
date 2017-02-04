#ifndef SERVER_H_
#define SERVER_H_

//Defaults and constants for SecCTP server
#define DEFAULT_SECCTP_PORT "5557"

#define KEYFILE "./certs/server-key.pem"
#define CERTFILE "./certs/cert.pem"
#define CAFILE "./certs/ca-cert.pem"

#define SENDQUEUE "/server_queue_snd"
#define RECVQUEUE "/server_queue_rcv"

#define WEB_DIR "webserver"

#define MAX_BUF 1024
#define WEBPORT "8888"
#define DONE -1

//Some useful constants for IPC  
#define MAX_SIZE 256
#define MSG_DIE "exit"
#define AUTHORIZED "auth"
#define NOT_AUTH "not auth"

#ifdef DEBUG
	#define debug_message(...) {fprintf(stderr, __VA_ARGS__); fflush(stderr);}
	#define on_error(...) {debug_message(__VA_ARGS__); fflush(stderr); return EXIT_FAILURE;}
#else
	#define debug_message(...){}
	#define on_error(...) {fprintf(stderr, __VA_ARGS__); fflush(stderr);}
#endif

#endif 

