#include <string>
#include <iostream>
#include <stdexcept>
#include <boost/regex.hpp>
#include "tins/tcp_ip/stream_follower.h"
#include "tins/sniffer.h"
#include "tins/ip_address.h"

#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <errno.h>


#include "../cpp_debug.hpp"

using std::string;
using std::cout;
using std::cerr;
using std::endl;
using std::exception;

using boost::regex;
using boost::match_results;

using Tins::Packet;
using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;
using Tins::IPv4Address;

#define AUTH_SIGNAL 303 //HTTP status code used to signal SecCTP transaction required
#define WEBPORT 8888

// Don't buffer more than 3kb of data in either request/response
const size_t MAX_PAYLOAD = 3 * 1024;

//Some regex defines to extract necessary data 
regex code_regex("HTTP/[^ ]+ ([\\d]+)"); 
regex request_regex("([\\w]+) ([^ ]+).+Host: ([\\d\\w\\.-]+)");
regex secctp_regex("([\\w]+) ([^ ]+).+SecCTP: ([\\d\\w\\.-]+)");

struct sockaddr_in serv_addr;
struct hostent *server;

void on_server_data(Stream& stream);
void on_client_data(Stream& stream);
void on_new_connection(Stream& stream);
int signalNIC(string server_addr, string host, string port);

int main(int argc, char* argv[]) {
    std::ostringstream oss; 
    oss << "tcp port " << WEBPORT; //Only interested in HTTP
    
    if (argc != 4) {
        on_error("Usage: ", argv[0], " <interface> <nic hostname/IP> <nic TCP port>");
        return 1;
    } try {		
		//A few extractions for the connection to the SecNIC over ethernet(TCP) 			
		if ( (server = gethostbyname(argv[2])) == NULL) {
			on_error("ERROR invalid server");
			return 1;
		}
		
		bzero((char *) &serv_addr, sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr,server->h_length);
		serv_addr.sin_port = htons(atoi(argv[3]));
						
        // Config and construct sniffer
        SnifferConfiguration config;        
        config.set_filter(oss.str());   
        Sniffer sniffer(argv[1], config);

        debug_message("Starting capture on interface ",argv[1]);

        // Construct and set up stream follower
        StreamFollower follower;        
        follower.new_stream_callback(&on_new_connection);
        sniffer.sniff_loop([&](Packet& packet) {
            follower.process_packet(packet);
            return true;
        });
    }
    catch (exception& ex) {
        on_error("Error: ", ex.what());
        return EXIT_FAILURE;
    }
}


/** Signal SecNIC when SecCTP transaction is required
 * 
 * @param server_addr IP address of SecCTP server as string
 * @param host		  Hostname of SeccTP server
 * @param port		  SecCTP port as string
 * 
 * @return Number of bytes transmitted or -1 in case of error
*/
int signalNIC(string server_addr, string host, string port) {
	int wc = -1;
	int sockfd;
	string msg;
	string delim = ":";
	std::ostringstream oss; 
	
	if ( (sockfd = socket(AF_INET,SOCK_STREAM,0)) < 0) {
			on_error("ERROR opening socket");
			return EXIT_FAILURE;
	}
	
	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) {
		on_error("ERROR connecting to server: ", errno);
		
	} else {
		/* Build msg, msg format to be hostname/resource-ipaddress:port (i.e. three tokens)*/	
		//URI from headers will be hostname-address:port		
		
		oss << host << "-" << server_addr << ":" << port << "\n";
		msg = oss.str();  
				
		//Send msg
		wc = write(sockfd, msg.data(), msg.length());			
		debug_message("msg ", msg);
		debug_message("Success wc= ",wc);
	}	
	close(sockfd);	
	return wc;
}

/** Callback function for server data 
 * 
 * 	@param stream	The associated Stream
 */
void on_server_data(Stream& stream) {
    match_results<Stream::payload_type::const_iterator> server_match;    
    match_results<Stream::payload_type::const_iterator> client_match;          
     
    const Stream::payload_type& server_payload = stream.server_payload();
    const Stream::payload_type& client_payload = stream.client_payload();        
    
    string response_code, host, port;
    
    // Run the regex on server payload
    bool matchFound = regex_search(server_payload.begin(), server_payload.end(),
                           server_match, code_regex) &&
                 regex_search(client_payload.begin(), client_payload.end(),
                              client_match, request_regex);
		
	//Output payload contents in debug mode
	debug_message("Client payload: ", endl, string(client_payload.begin(), client_payload.end()));
	debug_message("Server payload: ", endl, string(server_payload.begin(), server_payload.end()));
	
	//Ignores invalid or non-HTTP messages
	if (matchFound) {   		
        response_code = string(server_match[1].first, server_match[1].second);  							
		
		//If SecCTP auth required, extract necessary fields and signal SecNIC
		if (std::stoi(response_code) == AUTH_SIGNAL) {			
			debug_message("Processing authorization");
			 regex_search(server_payload.begin(), server_payload.end(),
                           server_match, secctp_regex);              
			IPv4Address server_addr = stream.server_addr_v4();
			debug_message(server_addr.to_string());
			
			host = string(client_match[3].first, client_match[3].second);
			port = string(server_match[3].first, server_match[3].second);
			if (signalNIC(server_addr.to_string(), host, port) < 0)
					on_error("Error in signaling SecNIC for auth");
		}		
        
    }
    
    stream.auto_cleanup_payloads(true);  //Dump the buffered data for 
    
    // Just in case the server returns invalid data, stop at 3kb
    if (stream.server_payload().size() > MAX_PAYLOAD) {
        stream.ignore_server_data();
    }
}

/** Callback function for server data 
 * 
 *  @param stream	The associated Stream
 */
void on_client_data(Stream& stream) {
	//Start buffering data on client requests
	stream.auto_cleanup_payloads(false); 		
}

/** Callback function for StreamFollower 
 * 
 *  @param stream	The associated Stream
 */
void on_new_connection(Stream& stream) {	   
	//Set up applicable callbacks and ignore data until client data 
    stream.server_data_callback(&on_server_data);	
    stream.client_data_callback(&on_client_data);
    stream.auto_cleanup_payloads(true);     
}
