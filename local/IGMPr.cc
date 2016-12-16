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

				unsigned int sourcecount = 0;
				for( HashMap<IPAddress, SrcRec>::iterator it = mcg.begin(); it != mcg.end(); ++it )
					sourcecount += it.value().srcs.size();

				WritablePacket *wp = Packet::make(34,0,
					(mcg.size()*grsize)+rsize+(1+sourcecount)*sizeof(uint32_t),0);
				igmpv3_report data;
				data.type = IGMP_REPORT;
				data.reserved1 = 0;
				data.sum = 0;
				data.reserved2 = 0;
				data.nogr = htons(mcg.size());
				uint32_t op = htonl(0x94040000);
				memcpy(wp->data(), &op, sizeof(uint32_t)); //IPv4 options before IGMP
				memcpy(wp->data()+4, &data, rsize); //report
				unsigned int count=0;
				for( HashMap<IPAddress, SrcRec>::iterator it = mcg.begin(); it != mcg.end(); ++it ) {
					igmpv3_grecord gr;
					if( it.value().inc ) gr.rtype = IGMP_MODE_IS_INCLUDE;
					else gr.rtype = IGMP_MODE_IS_EXCLUDE;
					gr.adl = 0;
					gr.nos = htons(it.value().srcs.size());
					gr.mcaddr = it.key().addr();
					memcpy(wp->data()+4+rsize+(count*grsize), &gr, grsize); //group record
					count++;
					for(unsigned int i=0; i < it.value().srcs.size(); i++) {
						uint32_t a = it.value().srcs[i].addr();
						memcpy(wp->data()+4+rsize+(count*grsize)+(i*sizeof(uint32_t)),
								&a, sizeof(uint32_t));
					}
				}
				uint16_t sum = click_in_cksum(wp->data()+4,
					rsize+(mcg.size()*grsize)+(sourcecount*sizeof(uint32_t)));
				memcpy(wp->data()+6, &sum, 2);
				output(1).push(wp);
				return;
			}
			else if( (*(uint32_t*)(p->data()+28)) != 0 and mcg.size() > 0 ) { 
			//group specific query, assuming we only need to respond with 1 group record...
				IPAddress ip(*(uint32_t*)(p->data()+28));
				SrcRec *sr = mcg.findp(ip);
				if( !sr ) return;
				WritablePacket *wp = Packet::make(34,0,
					grsize+rsize+(1+sr->srcs.size())*sizeof(uint32_t),0);
				igmpv3_report data;
				data.type = IGMP_REPORT;
				data.reserved1 = 0;
				data.sum = 0;
				data.reserved2 = 0;
				data.nogr = htons(1);
				uint32_t op = htonl(0x94040000);
				memcpy(wp->data(), &op, sizeof(uint32_t)); //IPv4 options before IGMP
				memcpy(wp->data()+4, &data, rsize); //report
				igmpv3_grecord gr;
				if( sr->inc ) gr.rtype = IGMP_MODE_IS_INCLUDE;
				else gr.rtype = IGMP_MODE_IS_EXCLUDE;
				gr.adl = 0;
				gr.nos = htons(sr->srcs.size());
				gr.mcaddr = (*(uint32_t*)(p->data()+28));
				memcpy(wp->data()+4+rsize, &gr, grsize); //group record
				for(unsigned int i=0; i < sr->srcs.size(); i++) {
					uint32_t a = sr->srcs[i].addr();
					memcpy(wp->data()+4+rsize+grsize+(i*sizeof(uint32_t)),
						&a, sizeof(uint32_t));
				}
				uint16_t sum = click_in_cksum(wp->data()+4,
					rsize+grsize+(sr->srcs.size()*sizeof(uint32_t)));
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
		for( HashMap<IPAddress, SrcRec>::iterator it = mcg.begin(); it != mcg.end(); ++it ) {
			if( IPAddress(p->ip_header()->ip_dst) == it.key() ) { //meaning we are listening
				//check the source
				bool found = false;
				for( unsigned int i=0; i < it.value().srcs.size(); i++ ) {
					if( it.value().srcs[i] == IPAddress(p->ip_header()->ip_src) ) {
						found = true;
						break;
					}
				}
				if( (found and it.value().inc) or (!found and !it.value().inc) ) {
					output(2).push(p);
					return;
				}
			}
		}
	}
	else output(0).push(p);
}

//helper function to remove duplicate IPs from a vector
void RemoveDuplicates(Vector<IPAddress>& ips)
{
	for(unsigned int i=0; i < ips.size(); i++) {
		for(unsigned int j=(i+1); j < ips.size(); j++)
		{
			if( ips[i] == ips[j] ) {
				ips.erase(ips.begin()+j);
				j--;
			}
		}	
	}
}

int IGMPr::join(const String &conf, Element *e, void * thunk, ErrorHandler * errh)
{	IGMPr * me = (IGMPr *) e;
	IPAddress ip;
	bool inc = false;
	Vector<IPAddress> srcs;
	if(cp_va_kparse(conf, me, errh, "GROUP", cpkP+cpkM, cpIPAddress, &ip, "INCLUDE", cpkP, cpBool, &inc, "SOURCES", cpkP, cpIPAddressList, &srcs, cpEnd) < 0) return -1;
	//perhaps schedule the join report later so multiple group-joins can be sent in one packet
	
	RemoveDuplicates(srcs);
	
	if( ip.is_multicast() ){
		bool oldinc = false;
		SrcRec *sr = me->mcg.findp(ip);
		if( sr ) {
			oldinc = sr->inc;
			sr->inc = inc;
			sr->srcs = srcs;
		} else {
			SrcRec sr;
			sr.inc = inc;
			sr.srcs = srcs;
			me->mcg.insert(ip, sr);
		}
		unsigned int rsize = sizeof(igmpv3_report);
		unsigned int grsize = sizeof(igmpv3_grecord);
		igmpv3_report data;
		data.type = IGMP_REPORT;
		data.reserved1 = 0;
		data.sum = 0;
		data.reserved2 = 0;
		data.nogr = htons(1);
		igmpv3_grecord gr;
		if( !sr and !inc ) gr.rtype = IGMP_CHANGE_TO_EXCLUDE;
		else if( !sr and inc ) gr.rtype = IGMP_MODE_IS_INCLUDE;
		else if( sr and oldinc != inc and inc == true) gr.rtype = IGMP_CHANGE_TO_INCLUDE;
		else if( sr and oldinc != inc and inc == false) gr.rtype = IGMP_CHANGE_TO_EXCLUDE;
		else if( sr and oldinc == inc and inc == false) gr.rtype = IGMP_MODE_IS_EXCLUDE;
		else if( sr and oldinc == inc and inc == true) gr.rtype = IGMP_MODE_IS_INCLUDE;
		gr.adl = 0;
		gr.nos = htons(srcs.size());
		gr.mcaddr = ip.addr();
		WritablePacket *p = Packet::make(34,0,(ntohs(data.nogr)*grsize)+rsize+sizeof(uint32_t)*(1+srcs.size()),0);
		if(p == 0) return -1;
		uint32_t op = htonl(0x94040000);
		memcpy(p->data(), &op, sizeof(uint32_t)); //IPv4 options before IGMP
		memcpy(p->data()+4, &data, rsize); //report
		memcpy(p->data()+4+rsize, &gr, grsize); //group record
		for(unsigned int i=0; i < srcs.size(); i++) {
			uint32_t a = srcs[i].addr();
			memcpy(p->data()+4+rsize+grsize+(i*sizeof(uint32_t)), &a, sizeof(uint32_t));\
		}
		uint16_t sum = click_in_cksum(p->data()+4, rsize+grsize+(srcs.size()*sizeof(uint32_t)));
		memcpy(p->data()+6, &sum, 2);
		me->output(1).push(p);
		return 0;	}
	else return -1;
}

//DO WE NEED TO SUPPORT THE ABILITY TO LEAVE FROM SPECIFIC SOURCES??? <- no because we can use a different handler
int IGMPr::leave(const String &conf, Element *e, void * thunk, ErrorHandler * errh)
{	IGMPr * me = (IGMPr *) e;
	IPAddress ip;
	if(cp_va_kparse(conf, me, errh, "GROUP", cpkP+cpkM, cpIPAddress, &ip, cpEnd) < 0) return -1;
	//perhaps schedule the leave report later so multiple group-leaves can be sent in one packet???
	if( ip.is_multicast() ){
		SrcRec *sr = me->mcg.findp(ip);
		if( sr ) {
			me->mcg.erase(ip);
		}
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
		gr.rtype = IGMP_CHANGE_TO_INCLUDE;
		gr.adl = 0;
		gr.nos = 0;
		gr.mcaddr = ip.addr();
		WritablePacket *p = Packet::make(34,0,(ntohs(data.nogr)*grsize)+rsize+sizeof(uint32_t),0);
		if(p == 0) return -1;
		uint32_t op = htonl(0x94040000);
		memcpy(p->data(), &op, sizeof(uint32_t)); //IPv4 options before IGMP
		memcpy(p->data()+4, &data, rsize); //report
		memcpy(p->data()+4+rsize, &gr, grsize); //group record
		uint16_t sum = click_in_cksum(p->data()+4, rsize+grsize);
		memcpy(p->data()+6, &sum, 2);
		me->output(1).push(p);
		return 0;
	}
	else return -1;
}

int IGMPr::sources(const String &conf, Element *e, void * thunk, ErrorHandler * errh)
{
	IGMPr * me = (IGMPr *) e;
	IPAddress ip;
	String act;
	Vector<IPAddress> srcs;
	if(cp_va_kparse(conf, me, errh, "GROUP", cpkP+cpkM, cpIPAddress, &ip,
		"ACTION", cpkP+cpkM, cpString, &act, 
		"SOURCES", cpkP, cpIPAddressList, &srcs, cpEnd) < 0) return -1;

	RemoveDuplicates(srcs);
	SrcRec *sr = me->mcg.findp(ip);
	if( !sr ) return -1; // meaning that the given multicast group is not present...

	if( act == "add" and srcs.size() > 0 ) { //meaning we want to add sources
		for( unsigned int i=0; i < srcs.size(); i++ ) { //only add sources that are not present
			bool found = false;
			for( unsigned int j=0; j < sr->srcs.size(); j++ ) {
				if( sr->srcs[j] == srcs[i] ) {
					found = true;
					break;
				}
			}
			if( !found ) sr->srcs.push_back(srcs[i]);
		}
	} else if( act == "del" and srcs.size() > 0 ) { //meaning we want to delete sources
		for( unsigned int i=0; i < srcs.size(); i++ ) { //only add sources that are not present
			for( unsigned int j=0; j < sr->srcs.size(); j++ ) {
				if( sr->srcs[j] == srcs[i] ) {
					sr->srcs.erase(sr->srcs.begin()+j);
					break;
				}
			}
		}
	} else if( act == "flush" ) { //meaning we want to clear the list of sources
		sr->srcs.clear();
	} else return -1; //meaning that we're dealing with a wrong use of the handler...	

	//generate state-change report
	unsigned int rsize = sizeof(igmpv3_report);
	unsigned int grsize = sizeof(igmpv3_grecord);
	WritablePacket *wp = Packet::make(34,0,
		grsize+rsize+(1+sr->srcs.size())*sizeof(uint32_t),0);
	igmpv3_report data;
	data.type = IGMP_REPORT;
	data.reserved1 = 0;
	data.sum = 0;
	data.reserved2 = 0;
	data.nogr = htons(1);
	uint32_t op = htonl(0x94040000);
	memcpy(wp->data(), &op, sizeof(uint32_t)); //IPv4 options before IGMP
	memcpy(wp->data()+4, &data, rsize); //report
	igmpv3_grecord gr;
	if( sr->inc ) gr.rtype = IGMP_MODE_IS_INCLUDE;
	else gr.rtype = IGMP_MODE_IS_EXCLUDE;
	gr.adl = 0;
	gr.nos = htons(sr->srcs.size());
	gr.mcaddr = ip.addr();
	memcpy(wp->data()+4+rsize, &gr, grsize); //group record
	for(unsigned int i=0; i < sr->srcs.size(); i++) {
		uint32_t a = sr->srcs[i].addr();
		memcpy(wp->data()+4+rsize+grsize+(i*sizeof(uint32_t)),
			&a, sizeof(uint32_t));
	}
	uint16_t sum = click_in_cksum(wp->data()+4,
		rsize+grsize+(sr->srcs.size()*sizeof(uint32_t)));
	memcpy(wp->data()+6, &sum, 2);
	me->output(1).push(wp);
	return 0;
}

int IGMPr::changemode(const String &conf, Element *e, void * thunk, ErrorHandler * errh)
{
	IGMPr * me = (IGMPr *) e;
	IPAddress ip;
	bool inc;
	Vector<IPAddress> srcs;
	if(cp_va_kparse(conf, me, errh, "GROUP", cpkP+cpkM, cpIPAddress, &ip,
		"INCLUDE", cpkP+cpkM, cpBool, &inc, 
		"SOURCES", cpkP, cpIPAddressList, &srcs, cpEnd) < 0) return -1;

	SrcRec *sr = me->mcg.findp(ip);
	if( !sr ) return -1; // meaning that the given multicast group is not present...

	bool statechanged = true;
	if( sr->inc != inc ) {
		sr->inc = inc;
	} else statechanged = false;
	
	if( statechanged ) {
		if( !srcs.empty() ) {
			RemoveDuplicates(srcs);
			sr->srcs = srcs;
		}

		//generate state-change report
		unsigned int rsize = sizeof(igmpv3_report);
		unsigned int grsize = sizeof(igmpv3_grecord);
		WritablePacket *wp = Packet::make(34,0,
			grsize+rsize+(1+sr->srcs.size())*sizeof(uint32_t),0);
		igmpv3_report data;
		data.type = IGMP_REPORT;
		data.reserved1 = 0;
		data.sum = 0;
		data.reserved2 = 0;
		data.nogr = htons(1);
		uint32_t op = htonl(0x94040000);
		memcpy(wp->data(), &op, sizeof(uint32_t)); //IPv4 options before IGMP
		memcpy(wp->data()+4, &data, rsize); //report
		igmpv3_grecord gr;
		if( sr->inc ) gr.rtype = IGMP_CHANGE_TO_INCLUDE;
		else gr.rtype = IGMP_CHANGE_TO_EXCLUDE;
		gr.adl = 0;
		gr.nos = htons(sr->srcs.size());
		gr.mcaddr = ip.addr();
		memcpy(wp->data()+4+rsize, &gr, grsize); //group record
		for(unsigned int i=0; i < sr->srcs.size(); i++) {
			uint32_t a = sr->srcs[i].addr();
			memcpy(wp->data()+4+rsize+grsize+(i*sizeof(uint32_t)),
				&a, sizeof(uint32_t));
		}
		uint16_t sum = click_in_cksum(wp->data()+4,
			rsize+grsize+(sr->srcs.size()*sizeof(uint32_t)));
		memcpy(wp->data()+6, &sum, 2);
		me->output(1).push(wp);
	}
	return 0;
}

String IGMPr::getgroups(Element *e, void * thunk)
{
	IGMPr * me = (IGMPr *) e;
	String groups;
	if( me->mcg.size() > 0 ) {
		for( HashMap<IPAddress, SrcRec>::iterator it = me->mcg.begin(); it != me->mcg.end(); ++it ) {
			groups += it.key().unparse();
			if( it.value().inc ) groups += " - Mode is include ";
			else groups += " - Mode is exclude "; 
			if( it.value().srcs.empty() ) groups += "with no sources.\n";
			else groups += "with sources:\n";
			for( unsigned int i=0; i < it.value().srcs.size(); i++ ) 
				groups += ("\t" + it.value().srcs[i].unparse() + "\n");
		}
	}
	else groups = "Not listening to any groups.\n";
	return groups;
}

void IGMPr::add_handlers()
{
	add_write_handler("join", &join, (void *)0);	add_write_handler("leave", &leave, (void *)0);
	add_write_handler("sources", &sources, (void *)0);	add_write_handler("mode", &changemode, (void *)0);
	add_read_handler("getgroups", &getgroups, (void *)0);}

CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPr)
