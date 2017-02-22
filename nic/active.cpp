#include <iostream>
#include <sstream>
#include "tins/tcp_ip/stream_follower.h"
#include "tins/sniffer.h"
#include "tins/packet.h"
#include "tins/ip_address.h"
#include "tins/ipv6_address.h"
#include <pthread.h>
#include <mqueue.h>
#include <errno.h>

#include "nic.h"
#include "../cpp_debug.hpp"

using std::cout;
using std::cerr;
using std::endl;
using std::bind;
using std::string;
using std::to_string;
using std::ostringstream;
using std::exception;
using std::multiset;

using Tins::Sniffer;
using Tins::SnifferConfiguration;
using Tins::PDU;
using Tins::TCPIP::StreamFollower;
using Tins::TCPIP::Stream;
using Tins::IPv4Address;

void on_new_connection(Stream& stream);
void on_connection_closed(Stream& stream);
void *monitor(void *args);

#define WEBPORT 8888

//List of active connection info ~ O(log n) insert/remove/find
// Demo requirements don't require further efficiency
multiset<Tins::IPv4Address> active;

int main(int argc, char* argv[]) {
    
    pthread_t thread;       
    mqd_t mq_snd;
    mqd_t mq_recv;
    
    char buffer[MAX_SIZE+1];
    ssize_t bytes_rcvd;
    std::string response = "";
    
    std::ostringstream oss; 
	oss << "tcp port " << WEBPORT; //Only interested in HTTP
    
    if (argc != 4) {
        on_error("Usage: ", argv[0]," <interface> <send mqueue name> <recv mqueue name>");
        return EXIT_FAILURE;
    }

    try {
        //Open the message queue for send/rec'd 
        if ( (mq_recv = mq_open(argv[2], O_RDONLY)) == (mqd_t) -1 || (mq_snd = mq_open(argv[3], O_WRONLY)) == (mqd_t) -1) {
			on_error("queue does not exist ", errno);
			return EXIT_FAILURE;
		}
			
        // Only capture TCP traffic sent from/to the given port
        SnifferConfiguration config;        
        config.set_filter("tcp port 8888");        
        Sniffer sniffer(argv[1], config);
		
        debug_message("Starting capture on interface ",argv[1]);
		//Create and join the thread and main
		if (pthread_create(&thread, NULL, monitor, (void *)&sniffer))
			return EXIT_FAILURE;        	
        //Inf loop until kill received from top level application
        while (1) {
			//Block on reading mqueue, act on message rec'd
			// Either kill signal or request to check a connection request
			bytes_rcvd = mq_receive(mq_recv, buffer, MAX_SIZE, NULL);			
			buffer[bytes_rcvd] = '\0';			
			if (0 == strncmp(buffer, MSG_DIE, strlen(MSG_DIE))) {					
				//Try to close mqueue and terminate
				if ( (mqd_t)-1 == mq_close(mq_snd) || (mqd_t)-1 == mq_close(mq_recv)) 
					return EXIT_FAILURE;
				return EXIT_SUCCESS;	
			} 
			else {				
				std::string addr(buffer);								
				IPv4Address check(addr);					
				(active.find(check) == active.end())? response =  NOT_FOUND: response = FOUND;					
				debug_message("sending from active ", response.c_str());
				if ( mq_send(mq_snd, response.c_str(), strlen(response.c_str()), 0) < 0) 
					on_error("error on send ", errno);			
			}			
		}		
    }
    catch (exception& ex) {
        on_error("Error: ", ex.what());
        return EXIT_FAILURE;
    }
}

/** Monitor function to run in sniffer thread
 * 
 *  @param args	Pointer to the previously set up Sniffer
 */
void *monitor(void *args){
	// construct the stream follower and run forever	
	Sniffer *sniffer = (Sniffer*)args;
	StreamFollower follower;
	follower.new_stream_callback(&on_new_connection);        
	(*sniffer).sniff_loop([&](PDU& packet) {
		follower.process_packet(packet);
		return true;
	});
	return NULL;
}

/** Callback function for StreamFollower for new connections
 * 
 *  @param stream	The associated Stream
 */
void on_new_connection(Stream& stream) {
    //Add new connect to list
    active.insert(stream.server_addr_v4());      
       
    //Only interested in the connections, not interested in the data
    stream.ignore_server_data();
    stream.ignore_client_data();    
        
    //Need to remove from list when connection is closed    
    stream.stream_closed_callback(&on_connection_closed);
    
    debug_message("Adding :  ", stream.server_addr_v4());        
}

/** Callback function for StreamFollower for finalized connections
 * 
 *  @param stream	The associated Stream
 */
void on_connection_closed(Stream& stream) {
    //Remove closed connect from list    
	active.erase(active.find(stream.server_addr_v4()));		
	
	debug_message("Removed :  ", stream.server_addr_v4());    
}
