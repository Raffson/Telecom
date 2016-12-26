// Output configuration: 
//
// Packets for the network are put on output 0
// Packets for the host are put on output 1

elementclass Client {
	$address, $gateway |

	ip :: Strip(14)
		-> CheckIPHeader()
		-> rt :: StaticIPLookup(
					$address:ip/32 0,
					$address:ipnet 0,
					0.0.0.0/0.0.0.0 $gateway 1)
		-> [1]output;
	
	rt[1]
		-> igmp :: IGMPr
		-> DropBroadcasts
		-> ipgw :: IPGWOptions($address)
		-> FixIPSrc($address)
		-> ttl :: DecIPTTL
		-> frag :: IPFragmenter(1500)
		-> arpq :: ARPQuerier($address)
		-> output;

	igmp[1]
		-> IPEncap(2, $address, multicast_report, TTL 1, TOS 0xc0)
		-> StoreData(0, F) //change IP header length to 6 for options
		-> SetIPChecksum
		-> EtherEncap(0x0800, $address, multicast_report)
		-> frag2 :: IPFragmenter(1500)
		-> output;

	igmp[2]
		-> [1]output;

	ipgw[1]
		-> ICMPError($address, parameterproblem)
		-> output;
	
	ttl[1]
		-> ICMPError($address, timeexceeded)
		-> output; 

	frag[1]
		-> ICMPError($address, unreachable, needfrag)
		-> output;

	frag2[1]
		-> ICMPError($address, unreachable, needfrag)
		-> output;

	// Incoming Packets
	input
		-> HostEtherFilter($address)
		-> in_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800)
		-> arp_res :: ARPResponder($address)
		-> output;

	in_cl[1]
		-> [1]arpq;
	
	in_cl[2]
		-> ip;
}
