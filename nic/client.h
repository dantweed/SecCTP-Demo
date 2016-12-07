//client.h

#ifndef CLIENT_H_
#define CLIENT_H_

#ifdef DEBUG
	#define debug_message(...) { wprintw(debugwin, __VA_ARGS__);wrefresh(debugwin);}
	#define on_error(...) {fprintf(stderr, __VA_ARGS__); fflush(stderr); return EXIT_FAILURE;}
#else
	#define debug_message(...){}
	#define on_error(...) {fprintf(stderr, __VA_ARGS__); fflush(stderr);}
#endif

#define LISTENPORT 5555 	//For incoming notifications from User PC
#define SECCTPPORT 5557  	//Assume defined standard port

#define MAX_BUF 1024
#define SENDQUEUE "/nic_queue_send"
#define RECVQUEUE "/nic_queue_recv"
#define CAFILE "./certs/cert.pem"  //TODO:generate new certs for distributed example
#define MSG_TOKENS 3
#define DONE -1

typedef struct serverDetails{
	char * hostname;
	char * resource;
	char * addr;
	int port;	
} serverDetails;

#endif
