/* Based on example code from the gnutls project. */

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

#include "../secctp.h"

#define CHECK(x) assert((x)>=0)
#define PORT  5557
#define SERVER  "127.0.0.1"

#define MAX_BUF 1024

#define CAFILE "./certs/cert.pem"

#define MSG "GET / HTTP/1.0\r\n\r\n"

gnutls_session_t session;
gnutls_certificate_credentials_t xcred;

int udp_connect_def(void);
int udp_connect(int port, const char *server);
int initgnutls(void);
void cleanup(int sd);
int dtls_connect(void);
int sendmessage(char *msg) ;
extern int verify_certificate_callback(gnutls_session_t session);

int main(int argc, char *argv[]) {

        int ret, sd, port;        
	char *server;
	char *msg = NULL; 
        /* connect to the peer */
	if (argc == 1) {
		printf("No server:port selected, using default: %s:PORT\n",SERVER);
		port = PORT;
		server = SERVER;
	} else if (argc != 3) {
	        printf("ERROR: Incorrect number of parameters.\n");
		printf("Correct usage is no parameters for default (%s:PORT) or\n",SERVER);
		printf("\t%s <server> <port>\n",argv[0]);
		exit(1);
	} else {
		port = atoi(argv[2]);
		server = argv[1];
	}
	
	if (initgnutls() < 0) {
		fprintf(stderr, "*** Error initializing gnutls.");
		goto end;
	}
	
	sd = udp_connect(port, server);

        gnutls_transport_set_int(session, sd);

        /* set the connection MTU */
        gnutls_dtls_set_mtu(session, 1000);
        /* gnutls_dtls_set_timeouts(session, 1000, 60000); */
	if (ret = dtls_connect() < 0)
		return ret;
		
	msg = (char *) malloc(MAX_SIZE);
	generateReq(msg,INFO,"127.0.0.1:5557","headers1\r\n", "this is req another body");
		
	if (msg) {
		ret = sendmessage(msg);
		free(msg);
		msg = NULL;
	}

	ret = gnutls_bye(session, GNUTLS_SHUT_WR);
	if (msg) free (msg);
    end:
	cleanup(sd);        

        return ret;
}

int dtls_connect(){
	int ret;
 	/* Perform the TLS handshake */
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

int sendmessage(char *msg) {
	int ret;
	char buffer[MAX_BUF + 1];
	

        CHECK(gnutls_record_send(session, msg, strlen(msg)));

        ret = gnutls_record_recv(session, buffer, MAX_BUF);
        if (ret == 0) {
                printf("- Peer has closed the TLS connection\n");                
        } else if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
                fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
        } else if (ret < 0) {
                fprintf(stderr, "*** Error: %s\n", gnutls_strerror(ret));
        } else if (ret > 0) {
		printf("- Received %d bytes: ", ret);
		for (int ii = 0; ii < ret; ii++) {
		        fputc(buffer[ii], stdout);
		}
		fputs("\n", stdout);
        }

    
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
        /* X509 stuff */
        ret = gnutls_certificate_allocate_credentials(&xcred);
	if (ret < 0)  return ret;
        /* sets the trusted cas file */
        ret = gnutls_certificate_set_x509_trust_file(xcred, CAFILE,GNUTLS_X509_FMT_PEM);
	if (ret < 0)  return ret;
        /* Initialize TLS session */
        ret = gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_DATAGRAM);
	if (ret < 0)  return ret;
        /* Use default priorities */
        ret = gnutls_set_default_priority(session);
	if (ret < 0)  return ret;
        /* put the x509 credentials to the current session */
        ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	if (ret < 0)  return ret;
        ret = gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost",strlen("localhost"));
	if (ret < 0)  return ret;
        gnutls_session_set_verify_cert(session, "localhost", 0);

	return ret;

}

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

