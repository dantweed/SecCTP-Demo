
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
#include <signal.h>

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
static volatile int trigger = 0;
int secCTPstep = 1;
mqd_t mq_snd;
mqd_t mq_rcv;

int initgnutls();
int processSecCTP(int sock);
void sigHandler(int sig);
void sigQueueHandler(int sig, siginfo_t *info, void *drop);
int udp_connect(int port, const char *server);

int web_pid;
int secCTPport;
transaction *trans = NULL; 


typedef struct {
        gnutls_session_t session;
        int fd;
        struct sockaddr *cli_addr;
        socklen_t cli_addr_size;
} priv_data_st;

int main(int argc, char **argv)
{
	int listen_sd;
	int sock;
	int optval;
	int own_pid;
	char pid_buf[10];
	char *webport;
	char *msg = NULL;
	struct sockaddr_in sa_serv;
	struct sockaddr_in clientaddr; 	
	socklen_t clientlen = sizeof(clientaddr);	 
	
	if (argc != 2) {
		secCTPport = atoi(DEFAULT_SECCTP_PORT);
		webport = WEBPORT;
	}
	else {
		secCTPport = atoi(argv[1]);	
		webport = argv[2];
	}
	debug_message("Server set webport %s\n", webport);
	
	struct mq_attr attr;	
	 /* Initialize the queues */
    attr.mq_flags = 0;
    attr.mq_maxmsg = 2;
    attr.mq_msgsize = MAX_SIZE;
    attr.mq_curmsgs = 0;
	if ( (mq_snd = mq_open(SENDQUEUE, O_WRONLY| O_CREAT, 0644, &attr)) == (mqd_t) -1) 
			on_error("Error opening queue %d", errno);	
	if ( (mq_rcv = mq_open(RECVQUEUE, O_RDONLY | O_CREAT, 0644, &attr)) == (mqd_t) -1) 
			on_error("Error opening queue %d", errno);	
	own_pid = getpid();
	
	//Launch webserver 
	if ( snprintf(pid_buf,10, "%d", own_pid) > 0 && (web_pid = fork()) == 0) { /* If queues open, run webserver in a separate process */	
		if (chdir(WEB_DIR) < 0)
			on_error("Error with chdir %d", errno);
		if ( (execl("web.exe", "web.exe", webport, SENDQUEUE, RECVQUEUE,  pid_buf, (char*) NULL)) < 0) 
			on_error("Error start webserver %d", errno);
	}
	debug_message("web %d\n", web_pid);
	
	//Handle signals 
	struct sigaction act, actQueue;
	memset(&act, 0, sizeof(act));
	act.sa_handler = &sigHandler;
	if ( ( sigaction(SIGINT, &act, NULL)) < 0)
		on_error("Error handling signal");				

	memset(&actQueue, 0, sizeof(actQueue));
	actQueue.sa_flags = SA_SIGINFO;
	actQueue.sa_sigaction = &sigQueueHandler;	

	if ( ( sigaction(SIGUSR2, &actQueue, NULL)) < 0)
		on_error("Error handling SIGUSR signal");		

	/* Try initializing gnutls*/
	if (initgnutls() < 0) 
		on_error("*** Error initializing gnutls.");	
	
	/* Socket operations */
	listen_sd = socket(AF_INET, SOCK_DGRAM, 0);
	
	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(secCTPport);

	{ /* DTLS requires the IP don't fragment (DF) bit to be set */
#if defined(IP_DONTFRAG)
	optval = 1;
	setsockopt(listen_sd, IPPROTO_IP, IP_DONTFRAG,
			   (const void *) &optval, sizeof(optval));
#elif defined(IP_MTU_DISCOVER)
	optval = IP_PMTUDISC_DO;
	setsockopt(listen_sd, IPPROTO_IP, IP_MTU_DISCOVER,
			   (const void *) &optval, sizeof(optval));
#endif
	}
	
	setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
	if ( bind(listen_sd, (struct sockaddr *) &sa_serv, sizeof(sa_serv)) < 0)
		on_error("ERROR on binding server 1%d", errno);
	printf("SecCTP server ready. Listening to port '%d'.\n\n", secCTPport);
	
	while (forever) { //Main loop - waits for connection from client or message from webserver		
		for (;forever && !trigger;) {			
			debug_message("Waiting for connection...\n");
			sock = wait_for_connection(listen_sd);		
			
			if (forever && sock > 0 )  /* else error on attempted connect */			
				processSecCTP(sock);	
			if (secCTPstep == 1) {
				
				listen_sd = socket(AF_INET, SOCK_DGRAM, 0);
				setsockopt(listen_sd, IPPROTO_IP, IP_MTU_DISCOVER,
					(const void *) &optval, sizeof(optval));
				setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
				if ( bind(listen_sd, (struct sockaddr *) &sa_serv, sizeof(sa_serv)) < 0)
					on_error("ERROR on binding server2 %d", errno);
			}
		}
		
		if (!forever)  //Program termination signal received
			close(listen_sd);
		else {  //Webserver requesting server initiated SecCTP transaction
			char buffer[MAX_SIZE+1];
			char resp[MAX_BUF];	
			struct sockaddr_in addr; 	
			socklen_t addrlen = sizeof(addr);
			int bytes_rcvd, ret, n, sd;	
			msgContents contents = {-1, NULL, NULL, NULL, NULL, -1, NULL};
			if ( (bytes_rcvd = mq_receive(mq_rcv, buffer, MAX_SIZE, NULL) ) <= 0) {
				on_error("Queue error %d",errno);
			}
			else {  //Valid request from webserver, send unsecured Hello msg to client
				buffer[bytes_rcvd] = '\0';
				if (!trans)
					trans = (transaction *) malloc(sizeof(transaction));
				
				if ( (ret = strcspn(buffer, ":")) == strlen(buffer)) 
					on_error("Invalid transaction\n");				
				buffer[ret] = '\0';			
				if ( inet_aton(buffer, &trans->client_addr) == 0)
					on_error("Invalid address\n");	
				char * addr = buffer;			
				if ( (trans->amount = atof(&buffer[ret+1]) ) <= 0) 
					on_error("Invalid transaction amount\n");
				
				if (!msg) msg = (char*)calloc(MAX_BUF, sizeof(char));
				if (msg && (ret = generateHello(msg, INFO, NULL, NULL)) < 0)
					on_error("Error generating Hello");
				if ((sd = udp_connect(secCTPport+1, addr)) < 0)
					on_error("Connection error on initial Hello");	   
				if ((n = send(sd, msg, strlen(msg), 0)) < 0)
					on_error("ERROR in send initial Hello");
				/* block on wait for client's reply */				
				if ( (n = recvfrom(sd, resp, MAX_BUF - 1, 0, (struct sockaddr *)&addr,  &addrlen)) < 0) 
				  	on_error("ERROR in recv initial Hello resp");
				resp[n] = '\0';
				debug_message("Response (%d bytes)= %s \n",n, resp);
			   /* parse response; if good, continue */ 
				if ( (ret = parseMessage(&contents, resp)) < 0) 
					on_error("Invalid server response to initial Hello\n");
				
				if (contents.type == RESP && contents.status == SECOK) {
					secCTPstep = 2; //Client will send DTLS hello as next step (handled by main FSM)
					close(sd);  
				}
				else {
					debug_message("Invalid server response type[%d] or status[%d]\nExpected type[%d] and status[%d]",contents.type,contents.status, RESP,SECOK);
					ret = -1;
				}	
				if (msg) {
					free(msg);
					msg = NULL;
				}	
			}
			if (contents.headers)
				free(contents.headers);
			trigger = 0;
		}
	}	
	
	//Clean up and close webserver	  
	if ( kill(web_pid, SIGTERM) < 0 ) 
		on_error("Error killing web server");
	mq_close(mq_snd);
	mq_close(mq_rcv);
	mq_unlink(SENDQUEUE);
	mq_unlink(RECVQUEUE);
	
	gnutls_certificate_free_credentials(x509_cred);
	gnutls_priority_deinit(priority_cache);

	gnutls_global_deinit();

	return EXIT_SUCCESS;
}

/** SecCTP transactions handled via multilevel state machine */
int processSecCTP(int sock) {
	
	struct sockaddr_in cli_addr;
	socklen_t cli_addr_size = sizeof(cli_addr);
	
	int ret = 0;
	int dtlsStep = 0;
	
	char buffer[MAX_BUF];
	char *msg = NULL;
	char * headers = NULL;
	msgContents contents = {-1, NULL, NULL, NULL, NULL, -1, NULL};
	
	priv_data_st priv;        
	gnutls_dtls_prestate_st prestate;
	int mtu = 1400;
	unsigned char sequence[8];	
	int authorized = 0;
	int attempts;	
	
	debug_message("Outer while, fd %d CTPstep %d dtlsStep %d\n",sock,secCTPstep,dtlsStep);		
	switch(secCTPstep) {
		case 1: /* Expecting unsecured hello message */ 	
			if (!msg) msg = (char*)calloc(MAX_BUF, sizeof(char));
			ret = recvfrom(sock, buffer, sizeof(buffer)-1, 0,
				   (struct sockaddr *) &cli_addr,
				   &cli_addr_size);
				   debug_message("Recvd,\n%s\n",buffer)
				  
			if (ret > 0) {
				// check if valid hello
					   /* parse msg; if good, continue */ 
				if ( (ret = parseMessage(&contents, buffer)) < 0) 
					on_error("Invalid hello: server\n");
				
				if (contents.type == HELLO ) { //Assume compatabilty on SecCTP version/protocols
					if ( (ret =  generateResp(msg, SECOK, NULL, NULL)) > 0 ) {		
						debug_message("server resp\n %s\n",msg);
						if ( (ret = sendto(sock, msg, strlen(msg), 0, (struct sockaddr *) &cli_addr,cli_addr_size)) > 0)   {            
							secCTPstep = 2;					
						} else  {
							on_error("Error sending resp \n");
						}
					} else {
						on_error("Errror generating resp \n");
					}
				}
				else {
					on_error("Error in hello recv %d\n", contents.type);	
					ret = -1;	
				}			
			}
			free (msg);
			msg = NULL;
			debug_message("End of initial hello: ret %d CTPstep %d\n",msg,secCTPstep);			
			break;
			
		case 2: /* Secured (DTLS) parts of the transaction */		
			dtlsStep = 1;
			debug_message("Inner while, fd %d CTPstep %d dtlsStep %d\n",sock,secCTPstep,dtlsStep);				
			while (dtlsStep <= 4 && dtlsStep != DONE && ret >= 0) {	
				switch(dtlsStep) { //Inner FSM for DTLS part
					case 1: /* DTLS Handshake */
						debug_message("Beginning handshake\n");
						ret = recvfrom(sock, buffer, sizeof(buffer), MSG_PEEK,
								(struct sockaddr *) &cli_addr,
								&cli_addr_size);
						if (ret > 0) {	
							//buffer[ret] = '\0';
							debug_message("1st dtls msg\n%s\n",buffer);
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
								continue; 
							}							
						} else {
							dtlsStep = DONE;
							break; //error on recieve to start handshake
						}
							
						//If otherwise good, move on to DTLS set up and handshake
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
						debug_message("Ready for actual handshake (%d)\n",ret);
						do {
								ret = gnutls_handshake(session);
						} while (ret == GNUTLS_E_INTERRUPTED|| ret == GNUTLS_E_AGAIN);

						if (ret < 0) {
							fprintf(stderr, "Error in handshake(%d): %s\n", ret,
									gnutls_strerror(ret));	 //Print error msg, but don't die	
							dtlsStep = DONE;			
						} 
						else 
							dtlsStep = 2;
						debug_message("Handshake compelted (%d)\n",ret);	
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
							debug_message("2nd DTKS msg\n%s\n",buffer);
							if ( (ret = parseMessage(&contents, buffer)) < 0) 
								on_error("Invalid message received\n");
			
							if (contents.type == HELLO ) { //Assume compatabilty for now
								if (!msg) msg = (char*)calloc(MAX_BUF, sizeof(char));
								if (!trans)
									ret =  generateResp(msg, SECOK, NULL, NULL);
								else {
									//Format transaction details to header and add to response
									headers = (char*)calloc(MAX_HEADER_SIZE, sizeof(char));
									if (headers == NULL)
										on_error("Memory allocation error");									
									sprintf(headers, "%s %.2lf\r\n", TRANS_TAG, trans->amount);
									ret =  generateResp(msg, UNAUTH, headers , NULL);
								}
								if ( ret > 0 ) {
									debug_message("DTLS resp\n%s\n",msg);
									if ( ( ret = gnutls_record_send(session, msg, strlen(msg)) ) > 0 ) 									
										dtlsStep = 3;					
								}
								
							}
							else 
								ret = -1;								
						}
						if (headers) {
							free(headers);
							headers = NULL;
						}
						if (trans) {
							free(trans);
							trans = NULL;
						}
						debug_message("after step2 ret %d\n",ret);
						break;
					case 3: /* Authentication */ 
						attempts = 0;
						while (ret > 0 && !authorized && attempts < AUTH_RETRIES) {
							
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
									on_error("Invalid message received\n");
								
								debug_message("3rd dtls msg\n%s\n",buffer);
								if (contents.type == REQ ) { 
									debug_message("Msg headers\n%s\n", contents.headers);								
									authorized = authorization(contents.headers);
									if (!msg) 
										msg = (char*)calloc(MAX_BUF, sizeof(char));
									else 
										msg[0] = '\0';
									if (authorized) 
										ret = generateResp(msg, SECOK, NULL, NULL);
									else {
										attempts++;
										if (attempts < AUTH_RETRIES)								
											ret =  generateResp(msg, UNAUTH, NULL, NULL);
										else 
											ret =  generateResp(msg, FORBIDDEN, NULL, NULL);
									}
									debug_message("dtls resp on ret %d\n%s\n",ret, msg);
									if ( ret > 0 ) { 										
										ret = gnutls_record_send(session, msg, strlen(msg));											
									}								
								}
								else {
									ret = -1;		
								}
														
							}	
						}//Auth while
						if (ret > 0 )
							dtlsStep = 4;					
						else
							dtlsStep = DONE;
						debug_message("End step3 ret %d\n",ret);
						break;						
					case 4: 
						debug_message("Final SecCTP step ret %d auth %d\n",ret,authorized);
						//pass back to webserver the authentication status												
						if (authorized) {
							ret = mq_send(mq_snd, AUTHORIZED, strlen(AUTHORIZED), 0);						
												
							debug_message("Msg sent (%d)\n", ret);
							if (ret < 0) {  
								on_error("Error in send (%d)\n", errno); 
							} else {
								union sigval auth;
								auth.sival_int = authorized;	
								
								if ( (ret = sigqueue(web_pid, SIGUSR2, auth)) < 0) {
									on_error("Error in signal (%d)\n",errno);
								} else {
									debug_message("Signal sent\n");	
								}
							}																												
						}
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
	
	//End transaction and clean up
	if (secCTPstep > 1 && (dtlsStep> 1 || dtlsStep == DONE) ) {
		secCTPstep = 1; //Reset outer switch condition 
		close(sock);		
		gnutls_bye(session, GNUTLS_SHUT_WR);
		gnutls_deinit(session);			
		debug_message("Socket closed and dtls session deinit\n");
	}
	
	if (msg) {
		free(msg);
		msg = NULL;
	}	

	if (contents.headers)
		free(contents.headers);
	
	if (dtlsStep == DONE && !authorized) //Failed at any step
		mq_send(mq_snd, NOT_AUTH, MAX_SIZE, 0);
	
	return ret;
}

/** Simple handling of SIGINT to cleanly close the applications */
void sigHandler(int sig) {
	forever = 0;
}

/** Signal to check webserver queue */
void sigQueueHandler(int sig, siginfo_t *info, void *drop) {	
	debug_message("SIGUSR rec'd\n");
	trigger = 1;
}

/************************************************************************/
/** GNUTLS initialization/maintenance functions based on gnutls examples*/
/** 		Public domain code											*/
/************************************************************************/
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
                on_error("select()");                
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
        gnutls_dh_params_init(&dh_params);
        gnutls_dh_params_generate2(dh_params, bits);

        return 0;
}

/* UDP helper function */ 
int udp_connect(int port, const char *server) {
        
	int err, sd, optval;
	struct sockaddr_in sa;

	/* connects to server using udp socket*/
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
	if (err < 0) 
		on_error("Connect error\n");		

	return sd;
}

