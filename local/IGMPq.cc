#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "IGMPq.hh"


CLICK_DECLS
IGMPq::IGMPq() : _t(this)
{}

IGMPq::~ IGMPq()
{}


int IGMPq::configure(Vector<String> &conf, ErrorHandler *errh) {
	_headroom = 34;
	_t.initialize(this);
	_qqic = 125;
	//_t.schedule_after_msec(_qqic*1000);
	if (cp_va_kparse(conf, this, errh, "QQIC", cpkP, cpUnsigned, &_qqic, "HEADROOM", cpkP, cpUnsigned, &_headroom, cpEnd) < 0) return -1;
	_t.schedule_after_msec(_qqic*1000);
	return 0;
}

void IGMPq::push(int, Packet* p)
{
	//print a message?
	p->kill();
}

void IGMPq::run_timer(Timer* t){
	igmpv3_query data;
	data.type = IGMP_QUERY;
	data.mrc = 100;
	data.sum = 0;
	data.gaddr = 0;
	data.resv = 0;
	data.s = 0;
	data.qrv = IGMP_DEFQRV;
	data.qqic = _qqic;
	data.nos = 0;
	data.sum = click_in_cksum((unsigned char *)(&data), 12);

	WritablePacket *p = Packet::make(_headroom,(const void*)(&data),sizeof(igmpv3_query),0);
	if(p == 0) {
		click_chatter("Cannot make IGMP packet!");
		return;
	}
	_t.schedule_after_msec(_qqic*1000);
	output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPq)
