#ifndef SERVER_H_
#define SERVER_H_

#define MAX_SIZE 256
#define MSG_DIE "exit"
#define AUTHORIZED "auth"
#define NOT_AUTH "not auth"
#define DEFAULT_SECCTP_PORT "5557"

#ifdef DEBUG
	#define debug_message(...) {fprintf(stderr, __VA_ARGS__); fflush(stderr);}
	#define on_error(...) {debug_message(__VA_ARGS__); fflush(stderr); return EXIT_FAILURE;}
#else
	#define debug_message(...){}
	#define on_error(...) {fprintf(stderr, __VA_ARGS__); fflush(stderr);}
#endif

#endif 
