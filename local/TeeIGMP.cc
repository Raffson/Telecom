#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "TeeIGMP.hh"


CLICK_DECLS
TeeIGMP::TeeIGMP()
{}

TeeIGMP::~ TeeIGMP()
{}


int TeeIGMP::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0) return -1;
	return 0;
}

void TeeIGMP::push(int, Packet* p)
{
	if( p->packet_type_anno() == 2 or p->dst_ip_anno().is_multicast() ) {
		for( unsigned int i=1; i < noutputs()-1; i++ ) {
			if (Packet *q = p->clone())
      				output(i).push(q);
		}
		output(noutputs()-1).push(p);
	}
	else output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(TeeIGMP)
