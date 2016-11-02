///===========================================================================///
/// Definitions of the different hosts and related address information.

// The idea is that instead of sending the data to a unicast address, it should be sent to 
// a multicast address and all clients subscribed to this multicast group receive the UDP 
// packet and print this out.

//wondering if ethernet address for multicast_client has to be used as well...
AddressInfo(multicast_client_address 225.1.1.1 01:00:5e:01:01:01) //originally 192.168.2.2 (unicast)
AddressInfo(multicast_query 224.0.0.1 01:00:5e:00:00:01)
AddressInfo(multicast_report 224.0.0.22 01:00:5e:00:00:16)