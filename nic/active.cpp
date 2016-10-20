	#include <iostream>
#include <sstream>
#include "tins/tcp_ip/stream_follower.h"
#include "tins/sniffer.h"
#include "tins/packet.h"
#include "tins/ip_address.h"
#include "tins/ipv6_address.h"

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
string server_endpoint(const Stream& stream);

multiset<Tins::IPv4Address> active;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <interface> " << endl;
        return 1;
    }

    try {
        // Construct the sniffer configuration object
        SnifferConfiguration config;
        // Only capture TCP traffic sent from/to the given port
        config.set_filter("tcp port 80");
        // Construct the sniffer we'll use
        Sniffer sniffer(argv[1], config);

        cout << "Starting capture on interface " << argv[1] << endl;

        // Now construct the stream follower
        StreamFollower follower;
        follower.new_stream_callback(&on_new_connection);        
        sniffer.sniff_loop([&](PDU& packet) {
            follower.process_packet(packet);
            return true;
        });
    }
    catch (exception& ex) {
        cerr << "Error: " << ex.what() << endl;
        return 1;
    }
}

void on_new_connection(Stream& stream) {
    // Print some information about the new connection
    cout << " [+] New connection " << server_endpoint(stream) << endl;    
    active.insert(stream.server_addr_v4());
    
    
    //Only interested in the connections, not interested in the data
    stream.ignore_server_data();
    stream.ignore_client_data();    
        
    //Need to remove from DB when connection is closed    
    stream.stream_closed_callback(&on_connection_closed);
}

void on_connection_closed(Stream& stream) {
    cout << " [-] Connection closed: " << server_endpoint(stream) << endl;        
	active.erase(active.find(stream.server_addr_v4()));
		
}

string server_endpoint(const Stream& stream) {
    ostringstream output;

    output << stream.server_addr_v4();
    output << ":" << stream.server_port();
    
    return output.str();
}



