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
 //Get the message code
regex code_regex("HTTP/[^ ]+ ([\\d]+)");
 //Search for SecCTP URI (assume hostname is same as main server, extract from active stream)
//regex uri_regex("([\\w]+) ([^ ]+).+\r\nSecCTP-URI: ((?:\"[^\"\n]*\"|[^\r\n])*)");  //format hostname:port per RFC 3986
//regex request_regex("([\\w]+) ([^ ]+).+\r\nHost: ([\\d\\w\\.-]+)\r\n");
//For testing and later, extracting all http headers
regex headers_regex("((?:\"[^\"\n]*\"|[^:,\n])*):((?:\"[^\"\n]*\"|[^,\n])*)");


int sockfd, portno, n;
struct sockaddr_in serv_addr;
struct hostent *server;

void on_server_data(Stream& stream);
void on_client_data(Stream& stream);
void on_new_connection(Stream& stream);
int signalNIC(string server_addr, string secCTP_uri);

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

int signalNIC(string server_addr, string uri) {
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
		//URI from headers will be hostname/resource:port
		oss << uri.substr(0,uri.find(delim)) << "-" << server_addr << ":" << uri.substr(uri.find(delim)+1) << "\n";
		msg = oss.str();
		
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
    
    // Run the regex on server payload
    bool valid = regex_search(server_payload.begin(), server_payload.end(),
                              server_match, code_regex); //&& 
                 regex_search(server_payload.begin(), server_payload.end(),
							client_match,headers_regex);// uri_regex);
	
    if (valid) {   		//string(client_match[2].first, client_match[2].second);
        string response_code = string(server_match[1].first, server_match[1].second);        		
		string secCTP_uri = string(client_match[3].first, client_match[3].second);	
	cout << "resp = " << response_code << "  uri= " << secCTP_uri << endl;
	cout << string(client_match[2].first, client_match[2].second)<< endl;
	cout << string(client_match[3].first, client_match[3].second)<< endl;
	cout << string(client_match[4].first, client_match[4].second)<< endl;
	
		if (std::stoi(response_code) == PROCESSING) {			
			IPv4Address server_addr = stream.server_addr_v4();
			cout << server_addr.to_string() << endl;			
			
			if (signalNIC(server_addr.to_string(), secCTP_uri) < 0)
				cerr << "Error in signaling SecNIC for auth" << endl;
		}
    }
    
    // Just in case the server returns invalid data, stop at 3kb
    if (stream.server_payload().size() > MAX_PAYLOAD) {
        stream.ignore_server_data();
    }
}

void on_new_connection(Stream& stream) {	
    stream.ignore_client_data(); //Only monitoring server messages for now
    stream.server_data_callback(&on_server_data);	
    stream.auto_cleanup_payloads(true); //No need to buffer the data
}


