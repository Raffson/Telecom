#ifndef CLICK_IGMPR_HH
#define CLICK_IGMPR_HH
#include <click/element.hh>
#include <clicknet/ip.h>
#include <click/hashmap.hh>
#include <click/timer.hh>
#include <stdlib.h>
#include <time.h>
#include "igmpv3.hh"

CLICK_DECLS

struct SrcRec {
	bool inc; //true if mode is include
	Vector<IPAddress> srcs; //list of sources that are either included or excluded
	Timer* gTimer; //group timer
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
		static int setsilent(const String &conf, Element *e, void * thunk, ErrorHandler * errh);
		static String getsilent(Element *e, void * thunk);
		static String getgroups(Element *e, void * thunk);
		void add_handlers();
	private:
		HashMap<IPAddress, SrcRec> mcg; //multicast groups
		bool silent;

		Timer iTimer; //interface timer
		struct iTimerData { //interface timer data
			IGMPr* me;
		};
		static void iHandleExpiry(Timer*, void *);
		void GQueryResponse(iTimerData *);

		struct gTimerData { //group timer data
			IGMPr* me;
			IPAddress group;
		};
		static void gHandleExpiry(Timer*, void *);
		void SQueryResponse(gTimerData *);
		
};

CLICK_ENDDECLS
#endif
