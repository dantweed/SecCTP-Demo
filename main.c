/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*-  */
/*
 * main.c
 * Copyright (C) 2016 Unknown <daniel@ArchLinux>
 * 
 * nic-client is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * nic-client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
#include <assert.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <netinet/in.h>

#define CHECK(x) assert((x)>=0)

#define MAX_BUF 1024

#define CAFILE "/home/daniel/SecNIC/nic/certs/cert.pem"

#define MSG "GET / HTTP/1.0\r\n\r\n"

extern int verify_certificate_callback(gnutls_session_t session);

int mtserver(int port);
int mtclient(int sd, gnutls_certificate_credentials_t *xcred, gnutls_session_t *session);

int cleanup (int sd, gnutls_certificate_credentials_t *xcred, gnutls_session_t *session ) ;
int udp_connect(int port, char *server);
void udp_close(int sd);

int main(int argc, char *argv [])
{
	int sd, port;	
	char *server;
	gnutls_session_t session;
	gnutls_certificate_credentials_t xcred; 
	
	if (argc == 3) {
		port = atoi(argv[2]);
		server = argv[1];		  
		
		/* connect to the peer */
		sd = udp_connect(port, server);
		mtclient(sd, &xcred, &session);

	}else {
		printf("Proper use is\n\t%s <server> <port>\n",argv[0]);
		return -1;
	}
	cleanup(sd, &xcred, &session);
	return 0;
}

int mtserver(int port) {  //To be defined
	return 0;
}

int mtclient(int sd, gnutls_certificate_credentials_t *xcred, gnutls_session_t *session){
	int ret, ii; 
        
    char buffer[MAX_BUF + 1];        

	if (gnutls_check_version("3.1.4") == NULL) {
		fprintf(stderr, "GnuTLS 3.1.4 or later is required for this example\n");
		exit(1);
	}

    /* for backwards compatibility with gnutls < 3.3.0 */
    CHECK(gnutls_global_init());

    /* X509 stuff */
    CHECK(gnutls_certificate_allocate_credentials(xcred));

    /* sets the trusted cas file */
    CHECK(gnutls_certificate_set_x509_trust_file(*xcred, CAFILE,GNUTLS_X509_FMT_PEM));

    /* Initialize TLS session */
    CHECK(gnutls_init(session, GNUTLS_CLIENT | GNUTLS_DATAGRAM));

    /* Use default priorities */
    CHECK(gnutls_set_default_priority(*session));

    /* put the x509 credentials to the current session */
    CHECK(gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, xcred));
    CHECK(gnutls_server_name_set(*session, GNUTLS_NAME_DNS, "localhost", strlen("localhost")));

    gnutls_session_set_verify_cert(*session, "localhost", 0);


    gnutls_transport_set_int(*session, sd);

    /* set the connection MTU */
    gnutls_dtls_set_mtu(*session, 1000);
    /* gnutls_dtls_set_timeouts(session, 1000, 60000); */

    /* Perform the TLS handshake */
    do {
            ret = gnutls_handshake(*session);
    }
    while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
    /* Note that DTLS may also receive GNUTLS_E_LARGE_PACKET */

    if (ret < 0) {
            fprintf(stderr, "*** Handshake failed\n");
            gnutls_perror(ret);
            goto end;
    } else {
            char *desc;

            desc = gnutls_session_get_desc(*session);
            printf("- Session info: %s\n", desc);
            gnutls_free(desc);
    }

    CHECK(gnutls_record_send(*session, MSG, strlen(MSG)));

    ret = gnutls_record_recv(*session, buffer, MAX_BUF);
    if (ret == 0) {
            printf("- Peer has closed the TLS connection\n");
            goto end;
    } else if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
            fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
    } else if (ret < 0) {
            fprintf(stderr, "*** Error: %s\n", gnutls_strerror(ret));
            goto end;
    }

    if (ret > 0) {
            printf("- Received %d bytes: ", ret);
            for (ii = 0; ii < ret; ii++) {
                    fputc(buffer[ii], stdout);
            }
            fputs("\n", stdout);
    }

    /* It is suggested not to use GNUTLS_SHUT_RDWR in DTLS
     * connections because the peer's closure message might
     * be lost */
    CHECK(gnutls_bye(*session, GNUTLS_SHUT_WR));

  end:        

    return 0;
}

int cleanup (int sd, gnutls_certificate_credentials_t *xcred, gnutls_session_t *session )  {
	
	close(sd);

    gnutls_deinit(*session);

    gnutls_certificate_free_credentials(*xcred);

    gnutls_global_deinit();

	return 0;
}

int udp_connect(int port, char *server){
        //const char *port = "5557";
        //const char *server = "127.0.0.1";
        int err, sd, optval;
        struct sockaddr_in sa;

        /* connects to server
         */
        sd = socket(AF_INET, SOCK_DGRAM, 0);

        memset(&sa, '\0', sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((port));//atoi(port)
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

