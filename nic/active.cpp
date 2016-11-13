#include <iostream>
#include <sstream>
#include "tins/tcp_ip/stream_follower.h"
#include "tins/sniffer.h"
#include "tins/packet.h"
#include "tins/ip_address.h"
#include "tins/ipv6_address.h"
#include <pthread.h>
#include <mqueue.h>

#include "nic.h"


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

multiset<Tins::IPv4Address> active;

int main(int argc, char* argv[]) {
    
    pthread_t thread;       
    mqd_t mq;
    char buffer[MAX_SIZE];
    ssize_t bytes_rcvd;
    std::string response = "";
    
    if (argc != 3) {
        cout << "Usage: " << argv[0] << " <interface> <mqueue name>" << endl;
        return EXIT_FAILURE;
    }

    try {//TODO: More meaningful exit codes
		
        //Open the message queue for send/rec'd 
        if ( (mq = mq_open(argv[2], O_RDWR)) == (mqd_t) -1) {
			cout << "queue does not exist" << endl;
			return EXIT_FAILURE;
		}
			
        // Only capture TCP traffic sent from/to the given port
        SnifferConfiguration config;        
        config.set_filter("tcp port 80");        
        Sniffer sniffer(argv[1], config);
		
        cout << "Starting capture on interface t" << argv[1] << endl;
		//Create and join the thread and main
		if (pthread_create(&thread, NULL, monitor, (void *)&sniffer))
			return EXIT_FAILURE;        
        		
        //Inf loop until kill received from top level applicationi
        while (1) {
			//block on reading mqueue, act on message rec'd
			bytes_rcvd = mq_receive(mq, buffer, MAX_SIZE-1, NULL);
			
			buffer[bytes_rcvd] = '\0';
			if (strncmp(buffer, MSG_DIE, strlen(MSG_DIE))) {						
				if ( (mqd_t)-1 == mq_close(mq) ) 
					return EXIT_FAILURE;
				return EXIT_SUCCESS;	
			} else {
				std::string addr = buffer;
				IPv4Address check(addr);
				(active.find(check) == active.end())? response =  NOT_FOUND: response = FOUND;	
				
				mq_send(mq, response.c_str(), MAX_SIZE, 0);
			}			
		}		
    }
    catch (exception& ex) {
        cerr << "Error: " << ex.what() << endl;
        return EXIT_FAILURE;
    }
}

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

void on_new_connection(Stream& stream) {
    //Add new connect to list
    active.insert(stream.server_addr_v4());    
    
    //Only interested in the connections, not interested in the data
    stream.ignore_server_data();
    stream.ignore_client_data();    
        
    //Need to remove from list when connection is closed    
    stream.stream_closed_callback(&on_connection_closed);
}

void on_connection_closed(Stream& stream) {
    //Remove closed connect from list
	active.erase(active.find(stream.server_addr_v4()));		
}
