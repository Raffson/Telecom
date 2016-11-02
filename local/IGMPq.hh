#ifndef CLICK_IGMPQ_HH
#define CLICK_IGMPQ_HH
#include <click/element.hh>
#include <clicknet/ip.h>
#include "igmpv3.hh"
#include <click/timer.hh>

CLICK_DECLS


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
	private:
		Timer _t;
		uint8_t _qqic; //qqic
		IPAddress _addr; //will use this to determine which interface we're on
		IPAddress _mask; //default 255.255.255.0
		Vector<IPAddress> _gtf; //vector of 'groups to forward'
		unsigned int _startup; //for startup query count, 8.7 RFC3376

		Packet* generateGroupSpecificQuery(const IPAddress& ip);
};

CLICK_ENDDECLS
#endif
