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


#define PROCESSING 102

// Don't buffer more than 3kb of data in either request/response
const size_t MAX_PAYLOAD = 3 * 1024;

//Some regex to extract necessary data
 //Get the status code
regex code_regex("HTTP/[^ ]+ ([\\d]+)");
 //Search for SecCTP URI (assume hostname is same as main server, extract from active stream)
//regex request_regex("([\\w]+) ([^ ]+).+\r\nHost: ([\\d\\w\\.-]+)\r\n");
regex request_regex("([\\w]+) ([^ ]+).+Host: ([\\d\\w\\.-]+)");
regex secctp_regex("([\\w]+) ([^ ]+).+SecCTP: ([\\d\\w\\.-]+)");



int sockfd, portno, n;
struct sockaddr_in serv_addr;
struct hostent *server;

void on_server_data(Stream& stream);
void on_client_data(Stream& stream);
void on_new_connection(Stream& stream);
int signalNIC(string server_addr, string uri, string url);

int main(int argc, char* argv[]) {
    if (argc != 4) {
        cout << "Usage: " << argv[0] << " <interface> <nic hostname/IP> <nic port>" << endl;
        return 1;
    } try {		
		//A few extractions for the connection to the SecNIC	    
		portno = atoi(argv[3]);		
		if ( (server = gethostbyname(argv[2])) == NULL) {
			cerr << "ERROR invalid server" << endl;
			return 1;
		}
		bzero((char *) &serv_addr, sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr,server->h_length);
		serv_addr.sin_port = htons(portno);
		
				
        // Config and construct sniffer
        SnifferConfiguration config;        
        config.set_filter("tcp port 8888"); //Only intersted in http         
        Sniffer sniffer(argv[1], config);

        cout << "Starting capture on interface " << argv[1] << endl;

        // Construct and set up stream follower
        StreamFollower follower;        
        follower.new_stream_callback(&on_new_connection);
        sniffer.sniff_loop([&](Packet& packet) {
            follower.process_packet(packet);
            return true;
        });
    }
    catch (exception& ex) {
        cerr << "Error: " << ex.what() << endl;
        return 1;
    }
}

int signalNIC(string server_addr, string host, string port) {
	int wc = -1;
	string msg;
	string delim = ":";
	std::ostringstream oss; 
	
	if ( (sockfd = socket(AF_INET,SOCK_STREAM,0)) < 0) {
			cerr << "ERROR opening socket" << endl;
			return 1;
	}
	
	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) {
		cerr << "ERROR connecting to server " << errno << endl;
		
	} else {
		/* Build msg, msg format to be hostname/resource-ipaddress:port (i.e. three tokens)*/	
		//URI from headers will be hostname-address:port		
		
		oss << host << "-" << server_addr << ":" << port << "\n";
		//msg = oss.str();  TODO: update client on nic to accept this message format
		msg = "localhost/pages/secure.html-127.0.0.1:5557";
		
		//Send msg
		wc = write(sockfd, msg.data(), msg.length());			
		cout << "msg " << msg << endl;
		cout << "Success wc " << wc << endl;
	}	
	close(sockfd);	
	return wc;
}

void on_server_data(Stream& stream) {
    match_results<Stream::payload_type::const_iterator> server_match;    
    match_results<Stream::payload_type::const_iterator> client_match;          
     
    const Stream::payload_type& server_payload = stream.server_payload();
    const Stream::payload_type& client_payload = stream.client_payload();        
    
    // Run the regex on server payload
    bool valid = regex_search(server_payload.begin(), server_payload.end(),
                           server_match, code_regex) &&
                 regex_search(client_payload.begin(), client_payload.end(),
                              client_match, request_regex);
		
	string clnt_data = string(client_payload.begin(), client_payload.end());
	string svr_data = string(server_payload.begin(), server_payload.end());
	cout << "client payload " << endl << clnt_data << endl;
	cout << "server payload " << endl << svr_data << endl;
	cout << "valid " << valid << endl;
	
    if (valid) {   		
        string response_code = string(server_match[1].first, server_match[1].second);  	
		string url = string(client_match[2].first, client_match[2].second);
		string host = string(client_match[3].first, client_match[3].second);			
		cout << "host "<< host << " url " << url << " resp = " << response_code << endl; 
		
		if (std::stoi(response_code) == 303) {	
			cout << "in processing"  << endl;
			 regex_search(server_payload.begin(), server_payload.end(),
                           server_match, secctp_regex);              
			IPv4Address server_addr = stream.server_addr_v4();
				cout << server_addr.to_string() << endl;			
			string port = string(server_match[3].first, server_match[3].second);
			if (signalNIC(server_addr.to_string(), host, port) < 0)
					cerr << "Error in signaling SecNIC for auth" << endl;			
		}		
        
    }
    
    stream.auto_cleanup_payloads(true);
    // Just in case the server returns invalid data, stop at 3kb
    if (stream.server_payload().size() > MAX_PAYLOAD) {
        stream.ignore_server_data();
    }
}

void on_client_data(Stream& stream) {
	stream.auto_cleanup_payloads(false);				
}

void on_new_connection(Stream& stream) {	    
    stream.server_data_callback(&on_server_data);	
    stream.client_data_callback(&on_client_data);
    stream.auto_cleanup_payloads(false); //No need to buffer the data
    
    
}


