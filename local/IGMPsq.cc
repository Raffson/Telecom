#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "IGMPsq.hh"


CLICK_DECLS
IGMPsq::IGMPsq()
{}

IGMPsq::~ IGMPsq()
{}


int IGMPsq::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
	return 0;
}

void IGMPsq::push(int, Packet* p)
{
/*
int n = 1;
// little endian if true
if(*(char *)&n == 1) click_chatter("little-endian");
else click_chatter("big-endian");
*/
	//this if-statement is practically useless because it should always be the case
	//but just to be sure we do this check...
	if( p->packet_type_anno() == 2 and p->ip_header() and p->ip_header()->ip_p == IP_PROTO_IGMP )
	{
		IPAddress ip((*(uint32_t*)(p->data()+42)));
		if( ip.addr() != 0 ) {
		//meaning that multicast address is not 0.0.0.0 and so this is group specific
			WritablePacket *wp = p->uniqueify();
			wp->set_dst_ip_anno(ip);
			click_ip *iph = wp->ip_header();
			iph->ip_dst = ip.in_addr();
			iph->ip_sum = 0;
			iph->ip_sum = click_in_cksum((unsigned char *)iph, 24);
			click_ether *eth = wp->ether_header();
			eth->ether_dhost[0] = 0x01;
			eth->ether_dhost[1] = 0x00;
			eth->ether_dhost[2] = 0x5e;
			eth->ether_dhost[3] = (ntohl(ip.addr()) & 0x00FF0000) >> 16;
			eth->ether_dhost[4] = (ntohl(ip.addr()) & 0x0000FF00) >> 8;
			eth->ether_dhost[5] = (ntohl(ip.addr()) & 0x000000FF);
			output(0).push(wp);
			return;
		}
	}
	output(0).push(p);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPsq)
