#ifndef SERVER_H_
#define SERVER_H_

#define MAX_SIZE 256
#define MSG_DIE "exit"
#define AUTHORIZED "auth"
#define NOT_AUTH "not auth"


#define on_error(...) {fprintf(stderr, __VA_ARGS__); fflush(stderr); return EXIT_FAILURE;}

#endif 
