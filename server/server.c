
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <mqueue.h>

#include "../secctp.h"
#include "server.h"

#define KEYFILE "./certs/service-key.pem"
#define CERTFILE "./certs/cert.pem"
#define CAFILE "./certs/ca-cert.pem"

#define QUEUE "/server_queue"

#define MAX_BUF 1024
#define PORT 5557
#define WEBPORT 8888
#define DONE -1

typedef struct {
        gnutls_session_t session;
        int fd;
        struct sockaddr *cli_addr;
        socklen_t cli_addr_size;
} priv_data_st;


static int pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms);
static ssize_t push_func(gnutls_transport_ptr_t p, const void *data,
                         size_t size);
static ssize_t pull_func(gnutls_transport_ptr_t p, void *data,
                         size_t size);
static const char *human_addr(const struct sockaddr *sa, socklen_t salen,
                              char *buf, size_t buflen);
static int wait_for_connection(int fd);
static int generate_dh_params(void);

/* Use global credentials and parameters to simplify implementation */
static gnutls_certificate_credentials_t x509_cred;
static gnutls_priority_t priority_cache;
static gnutls_dh_params_t dh_params;
gnutls_session_t session;
gnutls_datum_t cookie_key;

static volatile int forever = 1;
int secCTPstep;
mqd_t mq;


int initgnutls();
int processSecCTP(int sock);
void sigHandler(int sig);

int main(int argc, char **argv)
{
	int listen_sd;
	int sock, port, webport;
	struct sockaddr_in sa_serv;

	if (argc != 3) {
		port = PORT;
		webport = WEBPORT;
	}
	else {
		port = atoi(argv[1]);	
		webport = atoi(argv[2]);
	}
	
	struct mq_attr attr;	
	 /* initialize the queue attributes */
    attr.mq_flags = 0;
    attr.mq_maxmsg = 2;
    attr.mq_msgsize = MAX_SIZE;
    attr.mq_curmsgs = 0;
		
	if ( (mq = mq_open(QUEUE, O_RDWR | O_CREAT, 0644, &attr)) == (mqd_t) -1) 
		on_error("Error opening queue");		
	if (fork() == 0) { /* If queue is open, run monitor app in a separate process */	
		if ( (execl("http.exe", "http.exe", webport, QUEUE, (char*) NULL)) < 0) 
			on_error("Error start webserver");
	}				

	/* Try initializing gnutls*/
	if (initgnutls() < 0) 
		on_error("*** Error initializing gnutls.");	
	
	/* Socket operations */
	listen_sd = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(port);

	{ /* DTLS requires the IP don't fragment (DF) bit to be set */
#if defined(IP_DONTFRAG)
	int optval = 1;
	setsockopt(listen_sd, IPPROTO_IP, IP_DONTFRAG,
			   (const void *) &optval, sizeof(optval));
#elif defined(IP_MTU_DISCOVER)
	int optval = IP_PMTUDISC_DO;
	setsockopt(listen_sd, IPPROTO_IP, IP_MTU_DISCOVER,
			   (const void *) &optval, sizeof(optval));
#endif
	}

	bind(listen_sd, (struct sockaddr *) &sa_serv, sizeof(sa_serv));

	printf("UDP server ready. Listening to port '%d'.\n\n", port);
	while (forever) {
		for (;forever;) {
			printf("Waiting for connection...\n");
			sock = wait_for_connection(listen_sd);
			if (sock < 0 ) continue;  /* error on attempted connect */			
			processSecCTP(sock);	
		}
		close(listen_sd);
	}
	gnutls_certificate_free_credentials(x509_cred);
	gnutls_priority_deinit(priority_cache);

	gnutls_global_deinit();

	return 0;

}

int processSecCTP(int sock) {
	
	struct sockaddr_in cli_addr;
	socklen_t cli_addr_size = sizeof(cli_addr);
	
	int ret = 0;
	int dtlsStep;
	
	char buffer[MAX_BUF];
	char *msg = NULL;
	msgContents contents;
	
	priv_data_st priv;        
	gnutls_dtls_prestate_st prestate;
	int mtu = 1400;
	unsigned char sequence[8];	
	int authorized = 0;
	
	switch(secCTPstep) {
		case 1: /* Expect unsecured hello message */ 	
			if (!msg) msg = (char*)malloc(MAX_BUF);
			ret = recvfrom(sock, buffer, sizeof(buffer), 0,
				   (struct sockaddr *) &cli_addr,
				   &cli_addr_size);
			if (ret > 0) {
					   // check if valid hello
					   /* parse msg; if good, continue */ 
				if ( (ret = parseMessage(&contents, buffer)) < 0) 
					on_error("invalid response");
				
				if (contents.type == HELLO ) { //Assume compatabilty for now
					if ( (ret =  generateResp(msg, OK, NULL, NULL)) > 0 )
					 if ( (ret = sendto(sock, msg, sizeof(msg),0, (struct sockaddr *) &cli_addr,cli_addr_size)) > 0)               
						secCTPstep = 2;					
				}
				else 
					ret = -1;				
			}
			close(sock);
			if (msg) {
				free(msg);
				msg = NULL;
			}
			break;
		case 2: /* DTLS transaction */
			dtlsStep = 1;
			secCTPstep = 1; //Reset outer switch condition
			while (dtlsStep < 4 && dtlsStep != DONE && ret >= 0) {	
				switch(dtlsStep) {
					case 1: /* DTLS Handshake */
						ret = recvfrom(sock, buffer, sizeof(buffer), MSG_PEEK,
								(struct sockaddr *) &cli_addr,
								&cli_addr_size);
						if (ret > 0) {				
							/* dtls session and cookie setup */ 
							memset(&prestate, 0, sizeof(prestate));
							ret =
								gnutls_dtls_cookie_verify(&cookie_key,
														  &cli_addr,
														  sizeof(cli_addr),
														  buffer, ret,
														  &prestate);
							if (ret < 0) {  /* cookie not valid */
								priv_data_st s;

								memset(&s, 0, sizeof(s));
								s.fd = sock;
								s.cli_addr = (void *) &cli_addr;
								s.cli_addr_size = sizeof(cli_addr);				

								gnutls_dtls_cookie_send(&cookie_key,
														&cli_addr,
														sizeof(cli_addr),
														&prestate,
														(gnutls_transport_ptr_t)
														& s, push_func);

								/* discard peeked data */
								recvfrom(sock, buffer, sizeof(buffer), 0,
										 (struct sockaddr *) &cli_addr,
										 &cli_addr_size);
								usleep(100);
								continue;  //loop around and wait for valid cookie on next attempt (might need to limit this)
							}							
						} else
							break; //error on recieve to start handshake
						//If otherwqise good, move on to DTLS set up and handshake
							/* Set up GnuTLS for current session  */ 
						gnutls_init(&session, GNUTLS_SERVER | GNUTLS_DATAGRAM);
						gnutls_priority_set(session, priority_cache);
						gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
											   x509_cred);

						gnutls_dtls_prestate_set(session, &prestate);
						gnutls_dtls_set_mtu(session, mtu);

						priv.session = session;
						priv.fd = sock;
						priv.cli_addr = (struct sockaddr *) &cli_addr;
						priv.cli_addr_size = sizeof(cli_addr);

						gnutls_transport_set_ptr(session, &priv);
						gnutls_transport_set_push_function(session, push_func);
						gnutls_transport_set_pull_function(session, pull_func);
						gnutls_transport_set_pull_timeout_function(session,
																   pull_timeout_func);

						do {
								ret = gnutls_handshake(session);
						} while (ret == GNUTLS_E_INTERRUPTED|| ret == GNUTLS_E_AGAIN);

						if (ret < 0) {
							fprintf(stderr, "Error in handshake(%d): %s\n", ret,
									gnutls_strerror(ret));					
						} 
						else 
							dtlsStep = 2;
						break;
								
					/* Actual message passing*/
					case 2:  /* DTLS Hello */ 					
						do {
							ret =
								gnutls_record_recv_seq(session, buffer,
													   MAX_BUF,
													   sequence);
						} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

						if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
							fprintf(stderr, "*** Warning: %s\n",
									gnutls_strerror(ret));								
						} else if (ret < 0) {
							fprintf(stderr, "Error in recv(%d): %s\n",ret,
									gnutls_strerror(ret));								
						}

						if (ret > 0) {
							buffer[ret] = 0;
							if ( (ret = parseMessage(&contents, buffer)) < 0) 
								on_error("invalid message");
			
							if (contents.type == HELLO ) { //Assume compatabilty for now
								if (!msg) msg = (char*)malloc(MAX_BUF);
								if ( (ret =  generateResp(msg, OK, NULL, NULL)) > 0 )
									if ( ( ret = gnutls_record_send(session, msg, sizeof(msg)) ) > 0 ) 									
										dtlsStep = 3;					
							}
							else 
								ret = -1;								
						}							
						break;
					case 3: /* Authentication */ 
						do {
							ret =
								gnutls_record_recv_seq(session, buffer,
													   MAX_BUF,
													   sequence);
						} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

						if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
							fprintf(stderr, "*** Warning: %s\n",
									gnutls_strerror(ret));								
						} else if (ret < 0) {
							fprintf(stderr, "Error in recv(%d): %s\n",ret,
									gnutls_strerror(ret));								
						}

						if (ret > 0) {
							buffer[ret] = 0;
							if ( (ret = parseMessage(&contents, buffer)) < 0) 
								on_error("invalid message");
			
							if (contents.type == REQ ) { //TODO: validation of credentials
								//For now
								authorized = 1;
								if (!msg) msg = (char*)malloc(MAX_BUF);
								if ( (ret =  generateResp(msg, OK, NULL, NULL)) > 0 )
									if ( ( ret = gnutls_record_send(session, msg, sizeof(msg)) ) > 0 ) 									
										dtlsStep = 4;					
							}
							else 
								ret = -1;								
						}							
						break;						
					case 4: 
						//do the handoever to webserver of authentication status						
						if (authorized)
							mq_send(mq, AUTHORIZED, MAX_SIZE, 0);						
						dtlsStep = DONE;
						break;
					default:
						ret = -1; //error
				}//inner switch
			}//case 2 while
			break;  //case 2
		default: 
			ret = -1; //error
	}//outer switch	
	
	if (secCTPstep > 1) {
		close(sock);
		gnutls_bye(session, GNUTLS_SHUT_WR);
		gnutls_deinit(session);
	}
	if (msg) {
		free(msg);
		msg = NULL;
	}
	
	if (!authorized) //Failed at any step
		mq_send(mq, NOT_AUTH, MAX_SIZE, 0);
	
	return ret;
}

int initgnutls(){
	int ret;

    ret = gnutls_global_init();
	if (ret < 0)  return ret;
	
        /* Set up X.509 stuff */
    ret = gnutls_certificate_allocate_credentials(&x509_cred);
	if (ret < 0)  return ret;
	
        /* Set the trusted cas file */
    ret = gnutls_certificate_set_x509_trust_file(x509_cred, 
								CAFILE,GNUTLS_X509_FMT_PEM);
	if (ret < 0)  return ret;

	ret = gnutls_certificate_set_x509_key_file(x509_cred, CERTFILE, 
											 KEYFILE,
											 GNUTLS_X509_FMT_PEM);
	if (ret < 0) 
		on_error("No certificate or key were found\n");


	generate_dh_params();

	gnutls_certificate_set_dh_params(x509_cred, dh_params);

	gnutls_priority_init(&priority_cache,
		 "PERFORMANCE:-VERS-TLS-ALL:+VERS-DTLS1.0:%SERVER_PRECEDENCE",
		 NULL);

	gnutls_key_generate(&cookie_key, GNUTLS_COOKIE_KEY_SIZE);

	return ret;

}

static int wait_for_connection(int fd)
{
        fd_set rd, wr;
        int n;

        FD_ZERO(&rd);
        FD_ZERO(&wr);

        FD_SET(fd, &rd);

        /* waiting part */
        n = select(fd + 1, &rd, &wr, NULL, NULL);
        if (n == -1 && errno == EINTR)
                return -1;
        if (n < 0) {
                perror("select()");
                exit(1);
        }

        return fd;
}

/* Wait for data to be received within a timeout period in milliseconds
 */
static int pull_timeout_func(gnutls_transport_ptr_t ptr, unsigned int ms)
{
        fd_set rfds;
        struct timeval tv;
        priv_data_st *priv = ptr;
        struct sockaddr_in cli_addr;
        socklen_t cli_addr_size;
        int ret;
        char c;

        FD_ZERO(&rfds);
        FD_SET(priv->fd, &rfds);

        tv.tv_sec = 0;
        tv.tv_usec = ms * 1000;

        while (tv.tv_usec >= 1000000) {
                tv.tv_usec -= 1000000;
                tv.tv_sec++;
        }

        ret = select(priv->fd + 1, &rfds, NULL, NULL, &tv);

        if (ret <= 0)
                return ret;

        /* only report ok if the next message is from the peer we expect
         * from 
         */
        cli_addr_size = sizeof(cli_addr);
        ret =
            recvfrom(priv->fd, &c, 1, MSG_PEEK,
                     (struct sockaddr *) &cli_addr, &cli_addr_size);
        if (ret > 0) {
                if (cli_addr_size == priv->cli_addr_size
                    && memcmp(&cli_addr, priv->cli_addr,
                              sizeof(cli_addr)) == 0)
                        return 1;
        }

        return 0;
}

static ssize_t
push_func(gnutls_transport_ptr_t p, const void *data, size_t size)
{
        priv_data_st *priv = p;

        return sendto(priv->fd, data, size, 0, priv->cli_addr,
                      priv->cli_addr_size);
}

static ssize_t pull_func(gnutls_transport_ptr_t p, void *data, size_t size)
{
        priv_data_st *priv = p;
        struct sockaddr_in cli_addr;
        socklen_t cli_addr_size;
        char buffer[64];
        int ret;

        cli_addr_size = sizeof(cli_addr);
        ret =
            recvfrom(priv->fd, data, size, 0,
                     (struct sockaddr *) &cli_addr, &cli_addr_size);
        if (ret == -1)
                return ret;

        if (cli_addr_size == priv->cli_addr_size
            && memcmp(&cli_addr, priv->cli_addr, sizeof(cli_addr)) == 0)
                return ret;

        printf("Denied connection from %s\n",
               human_addr((struct sockaddr *)
                          &cli_addr, sizeof(cli_addr), buffer,
                          sizeof(buffer)));

        gnutls_transport_set_errno(priv->session, EAGAIN);
        return -1;
}

static const char *human_addr(const struct sockaddr *sa, socklen_t salen,
                              char *buf, size_t buflen)
{
        const char *save_buf = buf;
        size_t l;

        if (!buf || !buflen)
                return NULL;

        *buf = '\0';

        switch (sa->sa_family) {
#if HAVE_IPV6
        case AF_INET6:
                snprintf(buf, buflen, "IPv6 ");
                break;
#endif

        case AF_INET:
                snprintf(buf, buflen, "IPv4 ");
                break;
        }

        l = strlen(buf);
        buf += l;
        buflen -= l;

        if (getnameinfo(sa, salen, buf, buflen, NULL, 0, NI_NUMERICHOST) !=
            0)
                return NULL;

        l = strlen(buf);
        buf += l;
        buflen -= l;

        strncat(buf, " port ", buflen);

        l = strlen(buf);
        buf += l;
        buflen -= l;

        if (getnameinfo(sa, salen, NULL, 0, buf, buflen, NI_NUMERICSERV) !=
            0)
                return NULL;

        return save_buf;
}

static int generate_dh_params(void)
{
        int bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH,
                                               GNUTLS_SEC_PARAM_LEGACY);

        /* Generate Diffie-Hellman parameters - for use with DHE
         * kx algorithms. When short bit length is used, it might
         * be wise to regenerate parameters often.
         */
        gnutls_dh_params_init(&dh_params);
        gnutls_dh_params_generate2(dh_params, bits);

        return 0;
}

//Simple handling of SIGINT to cleanly close the applications
void sigHandler(int sig) {
	forever = 0;
}
