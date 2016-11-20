#ifndef CLICK_IGMPR_HH
#define CLICK_IGMPR_HH
#include <click/element.hh>
#include <clicknet/ip.h>
#include "igmpv3.hh"

CLICK_DECLS


class IGMPr : public Element { 
	public:
		IGMPr();
		~IGMPr();
		
		const char *class_name() const	{ return "IGMPr"; }
		const char *port_count() const	{ return "1/3"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);

		void push(int, Packet*);
		//Packet* pull(int);

		static int join(const String &conf, Element *e, void * thunk, ErrorHandler * errh);
		static int leave(const String &conf, Element *e, void * thunk, ErrorHandler * errh);
		static String getgroups(Element *e, void * thunk);
		void add_handlers();
	private:
		//uint32_t _headroom;
		Vector<IPAddress> mcg; //multicast groups
		
};

CLICK_ENDDECLS
#endif
