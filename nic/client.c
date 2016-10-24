/* Single-threaded for now*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <assert.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>

#include "../secctp.h" //Message definitions, etc 

#define on_error(...) {fprintf(stderr, __VA_ARGS__); fflush(stderr); exit(1);}

#define LISTENPORT 5555 	//For incoming notifications from User PC
//defaults for testing
#define SECCTPPORT  5557
#define SECCTPSERVER  "127.0.0.1" 

#define MAX_BUF 1024

#define CAFILE "./certs/cert.pem"

gnutls_session_t session;
gnutls_certificate_credentials_t xcred;

int udp_connect_def(void);
int udp_connect(int port, const char *server);
int initgnutls(void);
void cleanup(int sd);
int dtls_connect(void);
int sendmessage(char *msg, char *resp);

int processSecCTP(struct *sockaddr_in serveraddr);

extern int verify_certificate_callback(gnutls_session_t session);

int secCTPport;
char *secCTPserver;

int main(int argc, char *argv[]) {
	
	int parentfd;
	int childfd;
	int optval;
	socklen_t clientlen;
	int n;	
	
	int portno = LISTENPORT;  
	char buf[MAX_BUF];
	struct sockaddr_in serveraddr;
	struct sockaddr_in clientaddr; 
	struct sockaddr_in secCTPserver;
	/* validate args before bothering with anything else */
	
	if (argc == 1) {  //Used for debug on local machine only 
		printf("No server:port selected, using default: %s:%d\n",SECCTPSERVER,SECCTPPORT);
		secCTPport = SECCTPPORT;
		secCTPserver = SECCTPSERVER;
	} else if (argc != 3) {
	    on_error("Usage is %s <SecCTP server> <SecCTP port>\n",argv[0]);		
	} else {
		secCTPport = atoi(argv[2]);
		secCTPserver = argv[1];
	}
	
	/* set up tcp server socket */
	if ( (parentfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
		on_error("*** Error opening socket for tcp server");
		
	
	optval = 1;
	setsockopt(parentfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

	bzero((char *) &serveraddr, sizeof(serveraddr));  
	
	/* Bind to whatever our IP address is and selected port */
	serveraddr.sin_family = AF_INET;  
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);  
	serveraddr.sin_port = htons((unsigned short)portno);
	if (bind(parentfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) 
		on_error("ERROR on binding");
	
	/* If everything else checks out, try initializing gnutls*/

	if (initgnutls() < 0) 
		on_error("*** Error initializing gnutls.");
	
	
	if (listen(parentfd, 1) < 0)  /* only accept one connection at a time */ 
		on_error("ERROR on listen");
	
	
	/* Main loop */
	while (1) { /* Always be listening */ 	
		clientlen = sizeof(clientaddr);
		if ( (childfd = accept(parentfd, (struct sockaddr *) &clientaddr, &clientlen)) < 0) 
			on_error("ERROR on accept");	
		if ( (n = read(childfd, buf, MAX_BUF)) < 0) 
			on_error("Error on read");
	
	/* TODO: On accept, get request details and */
	//build sockaddr_in from message (if valid, otherwise log and drop)
	/* TODO: Validate session, then server in request via DNS, call functions for SecCTP transaction */ 
	ret = processSecCTP(&secCTPserver); //ret will be outcome of secctp trans in a defined struct
	}
	
	return EXIT_SUCCESS;
}


/*will be refactored as a step-based fsm to complete all steps of secctp trasnaction */
/*will assume for now only a single trasnactions (i.e. is blocking) */
int processSecCTP(struct sockaddr_in *serveraddr) { 
	char resp[MAX_BUF+1];
	char *msg;
	int secCTPsd;
	int ret;
	
	/* Set up upd connection and DTLS */
	secCTPsd = udp_connect(secCTPport, secCTPserver);    
	gnutls_transport_set_int(session, secCTPsd);
        /* set the connection MTU */
    gnutls_dtls_set_mtu(session, 1000);
        /* gnutls_dtls_set_timeouts(session, 1000, 60000); */
	if ( (ret = dtls_connect()) < 0)
		return ret;
	
	msg = (char*)malloc(MAX_BUF);
	if (msg) {
		ret = sendmessage(msg, resp);
		free(msg);
		msg = NULL;
	}


	/* clean up and close */ 
    
	ret = gnutls_bye(session, GNUTLS_SHUT_WR);
	if (msg) free (msg);    
 
	cleanup(secCTPsd);        

	/* needs to "return" outcome of the transaction to user pc */
    return ret;
}


int dtls_connect(){
	int ret;
 	/* Perform the TLS handshake */
	/* block until connected */
	do {
		ret = gnutls_handshake(session);
	}
	while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
	
	/* Note that DTLS may also receive GNUTLS_E_LARGE_PACKET */

	if (ret < 0) {
		fprintf(stderr, "*** Handshake failed\n");
		gnutls_perror(ret);
	} else {
		char *desc;

		desc = gnutls_session_get_desc(session);
		printf("- Session info: %s\n", desc);
		gnutls_free(desc);
	}
	return ret;
}	

int sendmessage(char *msg, char *resp) {
	int ret;	

	//send	
	ret =  gnutls_record_send(session, msg, strlen(msg));
	if (ret >= 0)  //If successful, receive
		ret = gnutls_record_recv(session, resp, MAX_BUF);
	
	if (ret == 0) 
		printf("- Peer has closed the TLS connection\n");                
	else if (ret < 0 && gnutls_error_is_fatal(ret) == 0) 
		fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
	else if (ret < 0) 
		fprintf(stderr, "*** Error: %s\n", gnutls_strerror(ret));
	else if (ret > 0)
		printf("- Received %d bytes: ", ret);	
	
	return ret;
}

void cleanup(int sd) {	
	if (sd > 0) close(sd);
	gnutls_deinit(session);
	gnutls_certificate_free_credentials(xcred);
	gnutls_global_deinit();
}

int initgnutls(){
	int ret;

	if (gnutls_check_version("3.1.4") == NULL) {
                fprintf(stderr, "GnuTLS 3.1.4 or later is required.\n");
                exit(1);
        }

        /* for backwards compatibility with gnutls < 3.3.0 */
        ret = gnutls_global_init();
	if (ret < 0)  return ret;
        /* Set up X.509 stuff */
        ret = gnutls_certificate_allocate_credentials(&xcred);
	if (ret < 0)  return ret;
        /* Set the trusted cas file */
        ret = gnutls_certificate_set_x509_trust_file(xcred, CAFILE,GNUTLS_X509_FMT_PEM);
	if (ret < 0)  return ret;
        /* Initialize TLS session */
        ret = gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_DATAGRAM);
	if (ret < 0)  return ret;
        /* Use default priorities */
        ret = gnutls_set_default_priority(session);
	if (ret < 0)  return ret;
        /* Set the X.509 credentials to the current session */
        ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	if (ret < 0)  return ret;
        ret = gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost",strlen("localhost"));
	if (ret < 0)  return ret;
        gnutls_session_set_verify_cert(session, "localhost", 0);

	return ret;

}

/* UDP helper function from gnutls example*/ 
int udp_connect(int port, const char *server)
{
        
        int err, sd, optval;
        struct sockaddr_in sa;

        /* connects to server
         */
        sd = socket(AF_INET, SOCK_DGRAM, 0);

        memset(&sa, '\0', sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        inet_pton(AF_INET, server, &sa.sin_addr);

#if defined(IP_DONTFRAG)
        optval = 1;
        setsockopt(sd, IPPROTO_IP, IP_DONTFRAG,
                   (const void *) &optval, sizeof(optval));
#elif defined(IP_MTU_DISCOVER)
        optval = IP_PMTUDISC_DO;
        setsockopt(sd, IPPROTO_IP, IP_MTU_DISCOVER,
                   (const void *) &optval, sizeof(optval));
#endif

        err = connect(sd, (struct sockaddr *) &sa, sizeof(sa));
        if (err < 0) {
                fprintf(stderr, "Connect error\n");
                exit(1);
        }

        return sd;
}

