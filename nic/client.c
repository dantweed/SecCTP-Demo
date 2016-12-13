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
#include <netdb.h>
#include <netinet/in.h>
#include <assert.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <mqueue.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>

//#define DEBUG

#include "../secctp.h" //Message definitions, etc 
#include "nic.h"	//defines for ipc communication
#include "client.h"

//TODO: move to curses UI instead of stdin
//#include <ncurses.h>
//TODO: after moving to curses UI, update all error handling

gnutls_session_t session;
gnutls_certificate_credentials_t xcred;

int udp_connect(int port, const char *server);
int initgnutls(void);
int reInitgnutls(void);
int dtls_connect(serverDetails *secCTPserver);
void dtls_deinit(void);
int sendDTLSmessage(char *msg, char *resp);
int processSecCTP(serverDetails *secCTPserver);
int validateServer(serverDetails *secCTPserver);
int parseUserPCmsg(serverDetails *secCTPserver, char *buf);
int userIO (char *resp, char *hostname);
void sigHandler(int sig);

extern int verify_certificate_callback(gnutls_session_t session);

mqd_t mq_snd;
mqd_t mq_recv;
static volatile int forever = 1;

int main(int argc, char *argv[]) {
	
	int parentfd;
	int childfd;
	int optval;
	socklen_t clientlen;
	int n, ret;	
	int portno = LISTENPORT;  
	pid_t synergy;
	char buf[MAX_BUF];

	struct sockaddr_in serveraddr;
	struct sockaddr_in clientaddr; 	
	
	struct sigaction act;
	
	serverDetails secCTPserver; 
	
	struct mq_attr attr;	
	 /* initialize the queue attributes */
    attr.mq_flags = 0;
    attr.mq_maxmsg = 2;
    attr.mq_msgsize = MAX_SIZE;
    attr.mq_curmsgs = 0;
		
	/* validate args before bothering with anything else */	
	//Used for debug on local machine only 
	if (argc != 2) {  		
	    on_error("Usage is %s <external facing interface>\n",argv[0]);		
	} else {
		/* Set up mqueue and launch active.cpp */ 
		if ( (mq_snd = mq_open(SENDQUEUE, O_WRONLY| O_CREAT, 0644, &attr)) == (mqd_t) -1) 
			on_error("Error opening queue %d", errno);	
		if ( (mq_recv = mq_open(RECVQUEUE, O_RDONLY | O_CREAT, 0644, &attr)) == (mqd_t) -1) 
			on_error("Error opening queue %d", errno);	
		if (fork() == 0) { /* If queues open, run monitor app in a separate process */	
			if ( (execl("active.exe", "active.exe", argv[1], SENDQUEUE, RECVQUEUE, (char*) 0)) < 0) 
				on_error("Error opening active monitor");
		}				
	}	
	
	memset(&act, '\0', sizeof(act));
	act.sa_handler = &sigHandler;
	if ( ( sigaction(SIGINT, &act, NULL)) < 0)
		on_error("Error handling signal %d", errno);
	/* set up tcp server socket */
	if ( (parentfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
		on_error("*** Error opening socket for tcp server %d", errno);	
	optval = 1;
	setsockopt(parentfd, SOL_SOCKET, SO_REUSEADDR|SO_REUSEPORT, (const void *)&optval , sizeof(int));

	bzero((char *) &serveraddr, sizeof(serveraddr)); 	
	/* Bind to whatever our IP address is and selected port */
	serveraddr.sin_family = AF_INET;  
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);  
	serveraddr.sin_port = htons((unsigned short)portno);
	if (bind(parentfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) 
		on_error("ERROR on binding %d", errno);
	
	/* If everything else checks out, try initializing gnutls*/
	if (initgnutls() < 0) 
		on_error("*** Error initializing gnutls");	
	
	if (listen(parentfd, 1) < 0)  /* only accept one connection at a time for now */ 
		on_error("ERROR on listen %d", errno);
    /*
    if ( (synergy = fork()) == 0) { // everything else checks out, start synergy for keyboard/mouse sharing	
		if ( (execl("/usr/bin/synergys", "synergys", "--address", "localhost:24800",(char*) NULL)) < 0) 
			on_error("1:Error starting synergy %d\n", errno);
	}	*/
    				
	/* Main loop */
	clientlen = sizeof(clientaddr);	
	while (forever) { /* Always be listening */ 	  //TODO: Expand to handle server initiated requests				
		
		debug_message("Waiting for msg from user PC\n", childfd);
		if ( (childfd = accept(parentfd, (struct sockaddr *) &clientaddr, &clientlen)) < 0 && forever) 
			on_error("ERROR on accept %d\n", errno);	
		debug_message("Rec'd mesg from user PC %d\n", childfd);
		if (forever && childfd > 0) { //Covers case of sig interupt out of accept block
		/* On accept, kill synergy for now and get request details 
			fprintf(stderr,"killing syn\n");fflush(stderr);
			if ( ( ret = kill(synergy, SIGTERM)) < 0 ) 
				on_error("Error killing synergy");
			synergy = 0; */	
			
			if ((n = read(childfd, buf, MAX_BUF)) < 0) 
				on_error("Error on read %d",errno);
			buf[n] = '\0';
			
		/* Validate session, then server in request via DNS, call functions for SecCTP transaction */ 
			if ( (ret = parseUserPCmsg(&secCTPserver,buf) != MSG_TOKENS)) 
				on_error("Invalid message from User PC\n");
			if ((ret = validateServer(&secCTPserver) != 0)) 
				on_error("Invalid server or request\n");
			
			//Outcome of SecCTP transaction
			debug_message("Begin secctp processing\n");
			if (forever && (ret = processSecCTP(&secCTPserver)) < 0) {
				on_error("after secctp %d\n",ret);
				break; //error condition
				
			}
			
			close(childfd);
			childfd = -1;
			/* Return keyboard control to user PC 
			if ( (synergy = fork()) == 0) { 
				if ( (execl("synergys", "synergys", (char*) NULL)) < 0) 
					on_error("2:Error starting synergy %d\n", errno);						
			}*/	
		}
		
	}
	/* Send kill to active.cpp application  */
	mq_send(mq_snd, MSG_DIE, strlen(MSG_DIE), 0);
	
	/* Clean up */ 	
	debug_message("Clean up queues and fd's"); 
	mq_close(mq_snd);
	mq_close(mq_recv);
	mq_unlink(SENDQUEUE);
	mq_unlink(RECVQUEUE);
	close(parentfd);
    dtls_deinit();
	/*
	if ( synergy && ( ret = kill(synergy, SIGTERM)) < 0 ) 
		on_error("Error killing synergy"); */
	return EXIT_SUCCESS;
}

/* Validates that this is an active session and validates server details */
int validateServer(serverDetails *secCTPserver) {
	struct addrinfo *res= NULL, *p, hints;
	int ret;
	int result = -1; //Assume no match
	int bytesRcvd;
	char ipstrComp[INET_ADDRSTRLEN+1];
	char buffer[MAX_SIZE+1];
	
	
	/* check if hostname/IP pair is valid request */		
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; 
	hints.ai_socktype = SOCK_STREAM;
	
	if ((ret = getaddrinfo(secCTPserver->hostname, NULL, &hints, &res)) != 0) 
		on_error("Error getting addr info: %s\n", gai_strerror(ret));		
	
	debug_message("Server address: %s\n",secCTPserver->addr);
	for(p = res;p != NULL && result != 0 ; p = p->ai_next) {		
		if (p->ai_family == AF_INET) { // IPv4			
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
			inet_ntop(AF_INET, &(ipv4->sin_addr), ipstrComp, INET_ADDRSTRLEN);			
			result = strncmp(ipstrComp, secCTPserver->addr, INET_ADDRSTRLEN);			
			debug_message("ipstrComp address: %s\n",ipstrComp);
		} // else ignore IPv6 for now			
	}

	freeaddrinfo(res); // free the linked list	
	
	if (result == 0) {
		/* check if valid active connection */
		strncpy(buffer, secCTPserver->addr, INET_ADDRSTRLEN);
		debug_message("SecCTP server addr  %s\n", buffer);
		mq_send(mq_snd, buffer, strlen(buffer), 0);
		/* wait for response */
		debug_message("Waiting for validation\n");
		bytesRcvd = mq_receive(mq_recv, buffer, MAX_SIZE, NULL);			
		buffer[bytesRcvd] = '\0';
		debug_message("Response buffer %s\n", buffer);
		if (strncmp(buffer, FOUND, strlen(FOUND)) != 0)
			result = -1; //Error: server not found in active connection list
	}	
	debug_message("End of server validation %d\n", result); 
	return result;
	
}

int parseUserPCmsg(serverDetails *secCTPserver, char *buf){	//TODO: update message format
	int count = 0;
	char *pch = strtok(buf, "-");
	
/* msg format to be hostname-address:port (i.e. 3 tokens)*/	
//
	if (pch != NULL) {
		secCTPserver->hostname = pch;
		count++;		
		pch = strtok(NULL, ":");		
	//	if (pch != NULL) {			
			secCTPserver->resource = "/"; //TODO: parse URI from pc req
	//		count++;			
	//		pch = strtok(NULL, ":");			
			if (pch != NULL) {				
				secCTPserver->addr = pch;
				count++;					
				pch = strtok(NULL, ":");
				if (pch != NULL) {					
					secCTPserver->port = atoi(pch);
					count++;					
				}
			}
	//	}		
	} 		
	return count;
}

/*will assume for now only a single trasnactions (i.e. is blocking) */

int processSecCTP(serverDetails *secCTPserver) { 
	char resp[MAX_BUF];
	char *msg = NULL;	
	int ret = 0;
	int sd,n;
	int step = 1;
	char *headers = NULL;
	char *creds = NULL;
	
	struct sockaddr_in svraddr; 	
	socklen_t svrlen = sizeof(svraddr);	
		
    msgContents contents = {-1, NULL, NULL, NULL, NULL, -1, NULL};
    
    while (step < 4 && step != DONE && ret >= 0) {
		debug_message("processSecCTP while, step %d\nport = %d\n",step,secCTPserver->port);
		switch(step) {
			case 1:	/* Send unsecure hello message */
				msg = (char*)malloc(MAX_BUF);
				if ((ret = generateHello(msg, INFO, NULL, NULL)) < 0)
					on_error("Error generating Hello");
				if ((sd = udp_connect(secCTPserver->port, secCTPserver->addr)) < 0)
					on_error("Connection error on initial Hello");	   
				if ((n = send(sd, msg, strlen(msg), 0)) < 0)
					on_error("ERROR in send initial Hello");	
				
				/* block on wait for server's reply */				
				if ( (n = recvfrom(sd, resp, MAX_BUF - 1, 0, (struct sockaddr *)&svraddr,  &svrlen)) < 0) 
				  	on_error("ERROR in recv initial Hello resp");
				resp[n] = '\0';
				debug_message("Respone (%d bytes)= %s \n",n, resp);
			   /* parse msg; if good, continue */ 
				if ( (ret = parseMessage(&contents, resp)) < 0) 
					on_error("Invalid sever response to initial Hello\n");
				
				if (contents.type == RESP && contents.status == OK) {
					step = 2;
					close(sd);  
				}
				else 
					ret = -1;
				break;
			case 2: /* Send DTLS hello message */				
				if ((sd = dtls_connect(secCTPserver)) > 0) {
					debug_message("DTLS connected,sending Hello \n");
					ret = sendDTLSmessage(msg, resp);
						/* parse msg; if good, continue */ //FIXME HERE
					if (ret > 0) 
						debug_message("Response:\n%s \n",resp);
					if ( ret > 0 && (ret = parseMessage(&contents, resp)) < 0) 
						on_error("Invalid sever response to Hello\n");					
					if (contents.type == RESP && contents.status == OK) 
						step = 3;
					else 
						ret = -2;						
				} 
				else 
					ret = -3;
				break;
			case 3: /* complete authentication transaction */  		
				creds = (char*)calloc(MAX_CRED_LENGTH,sizeof(char));
				if (creds != NULL && (ret = userIO(creds, secCTPserver->hostname)) < 0)
					on_error("error on user i/o");
					
				//After obtaining user credentials, format to header and transmit
				headers = (char*)calloc(MAX_HEADER_SIZE, sizeof(char));
				if (headers == NULL)
					on_error("memory allocation error");
					
				sprintf(headers, "Authorization: Basic %s", creds);//format =  Authorization: Basic username:password
				
				ret = generateReq(msg, GET, secCTPserver->resource, headers, NULL);
				ret = sendDTLSmessage(msg, resp);
				if ( ret > 0 && (ret = parseMessage(&contents, resp)) < 0) 
						on_error("Invalid SecCTP response");					
				if (contents.type == RESP && contents.status == OK) 
					step = 4;
				else 
					ret = -4;
				if(creds) free(creds);
				if(headers) free(headers);				
				break;
			case 4: 
			/* returning control to user PC */ 
			
				step = DONE;
				break;
		}
	}
	/* clean up and close */ 	
	debug_message("Before bye %d\n",ret);
	ret = gnutls_bye(session, GNUTLS_SHUT_WR); //0 is success
	debug_message("After bye %d\n",ret);
	gnutls_deinit(session);
	ret = reInitgnutls();
	debug_message("After deinit/reinit gnutlas %d\n",ret);
	if (msg) 
		free (msg); 
	if (contents.headers)
	    free(contents.headers); 
	close(sd);	
   	return ret;
}

/*Only handles authentication for now */
int userIO (char *resp, char *hostname){  //userIO (char *resp, char *hostname, int transType)
	int ret = -1;
	char uname[UNAME_LENGTH];
	char pwd[PWD_LENGTH];
	
	uname[0] = '\0';
	pwd[0] = '\0';
	
	/* to be changed to use curses at some point later */
	while(strlen(uname) == 0) {
		printf("[%s] Enter username: ", hostname);
		fgets(uname,UNAME_LENGTH,stdin);
		uname[strcspn(uname,"\r\n")] = '\0';		
	}
	
	while(strlen(pwd) == 0) {
		printf("[%s] Enter password: ", hostname);
		fgets(pwd,PWD_LENGTH,stdin);
		pwd[strcspn(pwd,"\r\n")] = '\0';
	}

	ret = sprintf(resp,"%s:%s\r\n",uname,pwd);		
	
	return ret;
}

int dtls_connect(serverDetails *secCTPserver){
	int ret;
	int secCTPsd;	

		/* Set the X.509 credentials to the current session */ 		
	ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	if (ret < 0)  return ret;
	
    	ret = gnutls_server_name_set(session, GNUTLS_NAME_DNS, secCTPserver->hostname,strlen(secCTPserver->hostname));
	if (ret < 0)  return ret;
    
	gnutls_session_set_verify_cert(session, secCTPserver->hostname, 0);
 	
 	/* Perform the TLS handshake */
	/* block until connected */
	/* Set up upd connection and DTLS */
	secCTPsd = udp_connect(secCTPserver->port, secCTPserver->addr);    
	gnutls_transport_set_int(session, secCTPsd);
        /* set the connection MTU */
	gnutls_dtls_set_mtu(session, 1000);
       
		
	do { 
		ret = gnutls_handshake(session);
	}
	while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
	
	/* Note that DTLS may also receive GNUTLS_E_LARGE_PACKET */

	if (ret < 0) {
		on_error("*** Handshake failed\n");
		gnutls_perror(ret);
	} else {
		/* For debugging */
		char *desc;		
		desc = gnutls_session_get_desc(session);		
		gnutls_free(desc);
			
		ret = secCTPsd;
	}
	return ret;
}	

int sendDTLSmessage(char *msg, char *resp) {
	int ret;	
    
	ret =  gnutls_record_send(session, msg, strlen(msg));
	if (ret >= 0)  //If successful, receive response
		ret = gnutls_record_recv(session, resp, MAX_BUF);
	
	if (ret < 0 && gnutls_error_is_fatal(ret) == 0) {
		debug_message("*** Warning: %s\n", gnutls_strerror(ret));
	} else if (ret < 0) {
		on_error("*** Error: %s\n", gnutls_strerror(ret));
	}
	return ret;
}

/* Initialization functions from gnutls dtls example */
int initgnutls(){
	int ret;

	if (gnutls_check_version("3.1.4") == NULL)
		on_error("GnuTLS 3.1.4 or later is required.\n");        

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

	return ret;
}

int reInitgnutls() {
	int ret;
	    /* Initialize TLS session */
    ret = gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_DATAGRAM);
	if (ret >= 0)         /* Use default priorities */
		ret = gnutls_set_default_priority(session);      
    return ret;
}

/* clean and close gnutls stuff */
void dtls_deinit() {	
	gnutls_deinit(session);
	gnutls_certificate_free_credentials(xcred);
	gnutls_global_deinit();
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

//Simple handling of SIGINT to cleanly close the applications
void sigHandler(int sig) {
	forever = 0;
}
