#ifndef CLICK_IGMPR_HH
#define CLICK_IGMPR_HH
#include <click/element.hh>
#include <clicknet/ip.h>
#include <click/hashmap.hh>
#include "igmpv3.hh"

CLICK_DECLS

struct SrcRec {
	bool inc; //true if mode is include
	Vector<IPAddress> srcs; //list of sources that are either included or excluded
};

class IGMPr : public Element { 
	public:
		IGMPr();
		~IGMPr();
		
		const char *class_name() const	{ return "IGMPr"; }
		const char *port_count() const	{ return "1/3"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);

		void push(int, Packet*);

		static int join(const String &conf, Element *e, void * thunk, ErrorHandler * errh);
		static int leave(const String &conf, Element *e, void * thunk, ErrorHandler * errh);
		static int sources(const String &conf, Element *e, void * thunk, ErrorHandler * errh);
		static int changemode(const String &conf, Element *e, void * thunk, ErrorHandler * errh);
		static String getgroups(Element *e, void * thunk);
		void add_handlers();
	private:
		//Vector<IPAddress> mcg; //multicast groups
		HashMap<IPAddress, SrcRec> mcg; //multicast groups
		
};

CLICK_ENDDECLS
#endif
