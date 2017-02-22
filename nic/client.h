#ifndef CLIENT_H_
#define CLIENT_H_

#ifdef DEBUG
	#define debug_message(...) { wprintw(debugwin, __VA_ARGS__);wrefresh(debugwin);}
	#define on_error(...) {debug_message(__VA_ARGS__);return EXIT_FAILURE;}
#else
	#define debug_message(...){}
	#define on_error(...) {fprintf(stderr, __VA_ARGS__); fflush(stderr);return EXIT_FAILURE;}
#endif

//Some useful constants
#define LISTENPORT 5555 	//For incoming notifications from User PC
#define SECCTPPORT 5557  	//Assume defined standard port

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

#define MAX_BUF 1024
#define SENDQUEUE "/nic_queue_send"
#define RECVQUEUE "/nic_queue_recv"
#define CAFILE "./certs/ca-cert.pem"  
#define MSG_TOKENS 3
#define DONE -1

//Convenience struct for server information
typedef struct serverDetails{
	char * hostname;
	char * resource;
	char * addr;
	int port;	
} serverDetails;

#endif
