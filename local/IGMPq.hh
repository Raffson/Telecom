#ifndef CLICK_IGMPQ_HH
#define CLICK_IGMPQ_HH
#include <click/element.hh>
#include <clicknet/ip.h>
#include "igmpv3.hh"
#include <click/timer.hh>
#include <click/hashmap.hh>


CLICK_DECLS

struct SrcRecRouter {
	IPAddress src; //source address
	//Timer st; //source timer
};

struct GrpRec {
	//Timer gt; //group timer
	bool inc; //filter mode, true if mode is include, false if mode is exclude
	Vector<SrcRecRouter> srcrecs; //source records
};


class IGMPq : public Element { 
	public:
		IGMPq();
		~IGMPq();
		
		const char *class_name() const	{ return "IGMPq"; }
		const char *port_count() const	{ return "1/2"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);

		void run_timer(Timer*);
		void push(int, Packet*);
		//Packet* pull(int);

		static int setqqic(const String &conf, Element *e, void * thunk, ErrorHandler * errh);
		static int setqrv(const String &conf, Element *e, void * thunk, ErrorHandler * errh);
		static String getqqic(Element *e, void * thunk);
		static String getqrv(Element *e, void * thunk);
		void add_handlers();
	private:
		Timer _t;
		uint8_t _qqic; //qqic
		uint8_t _qrv; //robustness variable
		uint8_t _startup; //for startup query count, 8.7 RFC3376
		//uint8_t _mrc; //max response code (leaving this for now since it involves timers)
		IPAddress _addr; //will use this to determine which interface we're on
		IPAddress _mask; //default 255.255.255.0
		HashMap<IPAddress, GrpRec> _gtf; //vector of 'groups to forward'

		Packet* generateGroupSpecificQuery(const IPAddress& ip);
};

CLICK_ENDDECLS
#endif
