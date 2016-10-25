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
		const char *port_count() const	{ return "0/1"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);

		void run_timer(Timer*);
		void push(int, Packet*);
		//Packet* pull(int);
	private:
		uint32_t _headroom;
		Timer _t;
		uint8_t _qqic; //qqic
		
};

CLICK_ENDDECLS
#endif
