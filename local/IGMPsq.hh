#ifndef CLICK_IGMPSQ_HH
#define CLICK_IGMPSQ_HH
#include <click/element.hh>
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include "igmpv3.hh"

CLICK_DECLS


class IGMPsq : public Element { 
	public:
		IGMPsq();
		~IGMPsq();
		
		const char *class_name() const	{ return "IGMPsq"; }
		const char *port_count() const	{ return "1/1"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);

		void push(int, Packet*);
};

CLICK_ENDDECLS
#endif
