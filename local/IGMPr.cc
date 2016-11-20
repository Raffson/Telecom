#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "IGMPr.hh"


CLICK_DECLS
IGMPr::IGMPr()
{}

IGMPr::~ IGMPr()
{}


int IGMPr::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
	return 0;
}

//STILL NEED TO DELAY REPORTS ACCORDING TO 'MAX RESP CODE'
void IGMPr::push(int, Packet* p)
{
	if( p->packet_type_anno() == 2 and p->ip_header() and p->ip_header()->ip_p == IP_PROTO_IGMP )
	{
		//all queries must be processed, regardless if the dest IP is unicast or multicast
		//so if dest IP equals the IP of this interface, it must process the query
		//therefore we would need the IP of this interface to compare the dest IP

		if( (*(p->data()+24)) == 0x11 ) { //meaning that we are dealing with a query...
			unsigned int rsize = sizeof(igmpv3_report);
			unsigned int grsize = sizeof(igmpv3_grecord);
			if( (*(uint32_t*)(p->data()+28)) == 0 and mcg.size() > 0 ) {
			//general query
				WritablePacket *wp = Packet::make(34,0,(mcg.size()*grsize)+rsize+sizeof(uint32_t),0);
				igmpv3_report data;
				data.type = IGMP_REPORT;
				data.reserved1 = 0;
				data.sum = 0;
				data.reserved2 = 0;
				data.nogr = htons(mcg.size());
				uint32_t op = htonl(0x94040000);
				memcpy(wp->data(), &op, sizeof(uint32_t)); //IPv4 options before IGMP
				memcpy(wp->data()+4, &data, rsize); //report
				//still need to account for aux data & number of sources
				//IGMPv3 does not define aux data, therefore always abscent!!!
				for( unsigned int i=0; i < mcg.size(); i++ ) {
					igmpv3_grecord gr;
					gr.rtype = IGMP_MODE_IS_EXCLUDE; //should need to look this up
					gr.adl = 0;
					gr.nos = 0;
					gr.mcaddr = mcg[i].addr();
					memcpy(wp->data()+4+rsize+(i*grsize), &gr, grsize); //group record
				}
				uint16_t sum = click_in_cksum(wp->data()+4, rsize+(mcg.size()*grsize));
				memcpy(wp->data()+6, &sum, 2);
				output(1).push(wp);
				return;
			}
			else if( (*(uint32_t*)(p->data()+28)) != 0 and mcg.size() > 0 ) { 
			//group specific query, assuming we only need to respond with 1 group record...
				bool missing = true;
				for( unsigned int i=0; i < mcg.size(); i++ ) {
					if( (*(uint32_t*)(p->data()+28)) == mcg[i].addr() ) missing = false;
				}
				if( missing ) return;
				WritablePacket *wp = Packet::make(34,0,grsize+rsize+sizeof(uint32_t),0);
				igmpv3_report data;
				data.type = IGMP_REPORT;
				data.reserved1 = 0;
				data.sum = 0;
				data.reserved2 = 0;
				data.nogr = htons(1);
				uint32_t op = htonl(0x94040000);
				memcpy(wp->data(), &op, sizeof(uint32_t)); //IPv4 options before IGMP
				memcpy(wp->data()+4, &data, rsize); //report
				//still need to account for aux data & number of sources
				//IGMPv3 does not define aux data, therefore always abscent!!!
				igmpv3_grecord gr;
				gr.rtype = IGMP_MODE_IS_EXCLUDE; //should need to look this up
				gr.adl = 0;
				gr.nos = 0;
				gr.mcaddr = (*(uint32_t*)(p->data()+28));
				memcpy(wp->data()+4+rsize, &gr, grsize); //group record
				uint16_t sum = click_in_cksum(wp->data()+4, rsize+grsize);
				memcpy(wp->data()+6, &sum, 2);
				output(1).push(wp);
				return;
			}
			else return; //meaning this host is not listening to any multicast address
		}
		//else silently ignore the packet (probably report from god knows who)
		else return;
	}
	//because we passed the 'StaticIPLookup' element, 'dst_ip_anno' is set to gateway
	//thus we need to apply another trick, i.e. IPAddress(p->ip_header()->ip_dst)
	else if( p->ip_header() and IPAddress(p->ip_header()->ip_dst).is_multicast() ) {
	//if it's a multicast packet to which we may be listening
		for( unsigned int i=0; i < mcg.size(); i++ ) {
			if( IPAddress(p->ip_header()->ip_dst) == mcg[i] ) { //meaning we are listening
				output(2).push(p);
				return;
			}
		}
	}
	else output(0).push(p);
}

int IGMPr::join(const String &conf, Element *e, void * thunk, ErrorHandler * errh)
{	IGMPr * me = (IGMPr *) e;
	IPAddress ip;
	if(cp_va_kparse(conf, me, errh, "GROUP", cpkP+cpkM, cpIPAddress, &ip, cpEnd) < 0) return -1;
	//perhaps schedule the join report later so multiple group-joins can be sent in one packet
	if( ip.is_multicast() ){
		//need to check if ip is allready present, don't add it again...
		//also need to pass the 'mode' as paramenter, may require a change...
		//if ip is present with the same mode, do nothing...
		bool missing = true;
		for( unsigned int i=0; i < me->mcg.size(); i++ )
			if( me->mcg[i] == ip ) missing = false;
		if( missing ) {
			me->mcg.push_back(ip);
		}
		//still need to check the mode, currently not implemented
		else return -1;
		unsigned int rsize = sizeof(igmpv3_report);
		unsigned int grsize = sizeof(igmpv3_grecord);
		igmpv3_report data;
		data.type = IGMP_REPORT;
		data.reserved1 = 0;
		data.sum = 0;
		data.reserved2 = 0;
		data.nogr = htons(1);
		igmpv3_grecord gr;
		gr.rtype = IGMP_CHANGE_TO_EXCLUDE; //needs to be given by parameter and stored for further use
		gr.adl = 0;
		gr.nos = 0;
		gr.mcaddr = ip.addr();
		WritablePacket *p = Packet::make(34,0,(ntohs(data.nogr)*grsize)+rsize+sizeof(uint32_t),0);
	//still need to account for the number of sources and aux data (for each group record)
	//IGMPv3 does not define aux data, therefore always abscent!!!
		if(p == 0) return -1;
		uint32_t op = htonl(0x94040000);
		memcpy(p->data(), &op, sizeof(uint32_t)); //IPv4 options before IGMP
		memcpy(p->data()+4, &data, rsize); //report
		memcpy(p->data()+4+rsize, &gr, grsize); //group record
	//still need to account for the number of sources and aux data (for each group record)
	//IGMPv3 does not define aux data, therefore always abscent!!!
		uint16_t sum = click_in_cksum(p->data()+4, rsize+grsize);
		memcpy(p->data()+6, &sum, 2);
		me->output(1).push(p);
		return 0;	}
	else return -1;
}

//DO WE NEED TO SUPPORT THE ABILITY TO LEAVE FROM SPECIFIC SOURCES???
int IGMPr::leave(const String &conf, Element *e, void * thunk, ErrorHandler * errh)
{	IGMPr * me = (IGMPr *) e;
	IPAddress ip;
	if(cp_va_kparse(conf, me, errh, "GROUP", cpkP+cpkM, cpIPAddress, &ip, cpEnd) < 0) return -1;
	//perhaps schedule the leave report later so multiple group-leaves can be sent in one packet???
	if( ip.is_multicast() ){
		bool missing = true;
		for( unsigned int i=0; i < me->mcg.size(); i++ ) {
			if( me->mcg[i] == ip ) {
				missing = false;
				me->mcg.erase(me->mcg.begin()+i);
			}
		}
		if( missing ) return -1;
		unsigned int rsize = sizeof(igmpv3_report);
		unsigned int grsize = sizeof(igmpv3_grecord);
		igmpv3_report data;
		data.type = IGMP_REPORT;
		data.reserved1 = 0;
		data.sum = 0;
		data.reserved2 = 0;
		data.nogr = htons(1);
		igmpv3_grecord gr;
		gr.rtype = IGMP_CHANGE_TO_INCLUDE;
		gr.adl = 0;
		gr.nos = 0;
		gr.mcaddr = ip.addr();
		WritablePacket *p = Packet::make(34,0,(ntohs(data.nogr)*grsize)+rsize+sizeof(uint32_t),0);
	//still need to account for the number of sources and aux data (for each group record)
	//IGMPv3 does not define aux data, therefore always abscent!!!
		if(p == 0) return -1;
		uint32_t op = htonl(0x94040000);
		memcpy(p->data(), &op, sizeof(uint32_t)); //IPv4 options before IGMP
		memcpy(p->data()+4, &data, rsize); //report
		memcpy(p->data()+4+rsize, &gr, grsize); //group record
	//still need to account for the number of sources and aux data (for each group record)
	//IGMPv3 does not define aux data, therefore always abscent!!!
		uint16_t sum = click_in_cksum(p->data()+4, rsize+grsize);
		memcpy(p->data()+6, &sum, 2);
		me->output(1).push(p);
		return 0;
	}
	else return -1;
}

String IGMPr::getgroups(Element *e, void * thunk)
{
	IGMPr * me = (IGMPr *) e;
	String groups;
	if( me->mcg.size() > 0 ) {
		for( unsigned int i=0; i < me->mcg.size(); i++ ) {
			groups += (me->mcg[i].unparse() + "\n");
		}
	}
	else groups = "Not listening to any groups.\n";
	return groups;
}

void IGMPr::add_handlers()
{
	add_write_handler("join", &join, (void *)0);	add_write_handler("leave", &leave, (void *)0);
	add_read_handler("getgroups", &getgroups, (void *)0);}

CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPr)
