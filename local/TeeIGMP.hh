#ifndef CLICK_TEEIGMP_HH
#define CLICK_TEEIGMP_HH
#include <click/element.hh>
#include <clicknet/ip.h>

CLICK_DECLS


class TeeIGMP : public Element { 
	public:
		TeeIGMP();
		~TeeIGMP();
		
		const char *class_name() const	{ return "TeeIGMP"; }
		const char *port_count() const	{ return "1/1-"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);

		void push(int, Packet*);
};

CLICK_ENDDECLS
#endif
