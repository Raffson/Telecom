#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "IGMPq.hh"


CLICK_DECLS
IGMPq::IGMPq() : _t(this), _qqic(125), _qrv(IGMP_DEFQRV), _startup(IGMP_DEFQRV), _mask(ntohl(0xFFFFFF00))
{}

IGMPq::~ IGMPq()
{}


int IGMPq::configure(Vector<String> &conf, ErrorHandler *errh) {
	_t.initialize(this);

	if (cp_va_kparse(conf, this, errh, "IP", cpkP+cpkM, cpIPAddress, &_addr, "QQIC", cpkP, cpByte, &_qqic, "QRV", cpkP, cpByte, &_qrv, "MASK", cpkP, cpIPAddress, &_mask, cpEnd) < 0) return -1;
	unsigned int qqi = _qqic;
	if( qqi >= 128 ) {
		uint8_t mant = 255 & 0x0F;
		uint8_t exp = (255 & 0x70) >> 4;
		qqi = (mant | 0x10) << (exp+3);
	}
	if( _qrv > 7 ) {
		_qrv = 0;
		_startup = 0;
		_t.schedule_after_msec(qqi*1000); //no startup because qrv = 0
	}
	else {
		_t.schedule_after_msec(qqi*250); //startup query interval, 1/4 of the QQIC as stated in 8.6
		_startup = _qrv;
	}
	return 0;
}

void IGMPq::push(int, Packet* p)
{
	//respond to leave reports with a group specific query
	//also determine if the report came from the same interface -> done
	//receiving the multicast source (UDP) packets here too
	//must determine whether or not we must forward the multicast source
	//upon receiving join reports, we must start forwarding -> done
	//we should be dealing only with IGMP or multicast IP packets
	if( p->packet_type_anno() == 2 and p->ip_header() and p->ip_header()->ip_p == IP_PROTO_IGMP ) {
		//IGMP join or leave?
		uint32_t subnet = _addr.addr() & _mask.addr();
		if( (p->ip_header()->ip_src.s_addr & _mask.addr()) == subnet ) {
			//meaning we're on the same interface?
			if( (*(p->data()+32)) == 0x04 ) {
			//change to exclude, without sources this represents a join
				//mode is change to exclude which corresponds with join if number of sources is 0
				//we must still mind that it could be change to include mode with sources...
				//for now, we keep it simple...
				_gtf.push_back(IPAddress((*(uint32_t*)(p->data()+36))));
			}
			else if( (*(p->data()+32)) == 0x03 ) {
			//change to include, without sources this represents a leave
				//same story here as in the if-part...
				//now we need to generate a group specific query
				//if no response is sent, we stop forwarding
				IPAddress del((*(uint32_t*)(p->data()+36)));
				for( unsigned int i=0; i < _gtf.size(); i++ ) {
					if( _gtf[i] == del ) {
						_gtf.erase(_gtf.begin()+i);
						break;
					}
				}
				//generate IP header for group specific query and group specific query itself...
				Packet* q = generateGroupSpecificQuery(del);
				output(1).push(q);
			}
		}
	}
	else if( p->ip_header() and p->dst_ip_anno().is_multicast() ) {
		//multicast source?
		//currently we compare to a simple vector & check if the multicast address is present
		for( unsigned int i=0; i < _gtf.size(); i++ ) {
			if( _gtf[i] == p->dst_ip_anno() ) {
				output(0).push(p);
				return;
			}
		}
	}
	//else nothing?
}

//generates general queries
void IGMPq::run_timer(Timer* t){
	igmpv3_query data;
	data.type = IGMP_QUERY;
	data.mrc = 100;
	data.sum = 0;
	data.mcaddr = 0;
	data.resv = 0;
	data.s = 0;
	data.qrv = _qrv;
	data.qqic = _qqic;
	data.nos = 0;
	data.sum = click_in_cksum((unsigned char *)(&data), 12);

	WritablePacket *p = Packet::make(34,0,sizeof(igmpv3_query)+sizeof(uint32_t),0);
	if(p == 0) {
		click_chatter("Cannot make IGMP packet!");
		return;
	}
	uint32_t op = htonl(0x94040000); //options for IPv4 header
	memcpy(p->data(), &op, sizeof(uint32_t)); //put IPv4 options before IGMP
	memcpy(p->data()+4, &data, sizeof(igmpv3_query)); //IGMP data
	p->set_packet_type_anno(Packet::MULTICAST);

	//still need to account for qqic > 128, do the math to get QQI
	unsigned int qqi = _qqic;
	if( qqi >= 128 ) {
		uint8_t mant = 255 & 0x0F;
		uint8_t exp = (255 & 0x70) >> 4;
		qqi = (mant | 0x10) << (exp+3);
	} 
	if( _startup > 1 ) { //as stated in 8.7 RFC3376
		_t.schedule_after_msec(qqi*250);
		_startup--;
	}
	else _t.schedule_after_msec(qqi*1000);
	output(1).push(p);
}

Packet* IGMPq::generateGroupSpecificQuery(const IPAddress& ip)
{
	igmpv3_query data;
	data.type = IGMP_QUERY;
	data.mrc = 50;
	data.sum = 0;
	data.mcaddr = ip.addr();
	data.resv = 0;
	data.s = 1;
	data.qrv = _qrv;
	data.qqic = _qqic;
	data.nos = 0;
	data.sum = click_in_cksum((unsigned char *)(&data), 12);

	WritablePacket *p = Packet::make(34,0,sizeof(igmpv3_query)+sizeof(uint32_t),0);
	if(p == 0) {
		click_chatter("Cannot make IGMP packet!");
		return 0;
	}
	uint32_t op = htonl(0x94040000); //options for IPv4 header
	memcpy(p->data(), &op, sizeof(uint32_t)); //put IPv4 options before IGMP
	memcpy(p->data()+4, &data, sizeof(igmpv3_query)); //IGMP data
	p->set_packet_type_anno(Packet::MULTICAST);
	return p;
}

//If no parameter is specified, we use the default value of 125
int IGMPq::setqqic(const String &conf, Element *e, void * thunk, ErrorHandler * errh)
{	IGMPq * me = (IGMPq *) e;
	uint32_t qqic = 125;
	if(cp_va_kparse(conf, me, errh, "QQIC", cpkP, cpUnsigned, &qqic, cpEnd) < 0) return -1;
	if( qqic > 255 ) me->_qqic = 255; //QQIC is 1 byte (unsigned), so top off at 255
	else me->_qqic = qqic;
	//should check mrc if we will use it, otherwise set mrc equal to qqic because RFC states QQIC >= MRC
	return 0;
}

//If no parameter is specified, we use the default value of 2
int IGMPq::setqrv(const String &conf, Element *e, void * thunk, ErrorHandler * errh)
{	IGMPq * me = (IGMPq *) e;
	uint32_t qrv = IGMP_DEFQRV;
	if(cp_va_kparse(conf, me, errh, "QRV", cpkP, cpUnsigned, &qrv, cpEnd) < 0) return -1;
	if( qrv > 7 ) me->_qrv = 0;
	else me->_qrv = qrv;
	return 0;
}

String IGMPq::getqqic(Element *e, void * thunk)
{
	IGMPq *me = (IGMPq *) e;
	String qqic((int)(me->_qqic));
	qqic += "\n";
	return qqic;
}

String IGMPq::getqrv(Element *e, void * thunk)
{
	IGMPq *me = (IGMPq *) e;
	String qrv((int)(me->_qrv));
	qrv += "\n";
	return qrv;
}

void IGMPq::add_handlers()
{
	add_write_handler("qqic", &setqqic, (void *)0);	add_write_handler("qrv", &setqrv, (void *)0);	add_read_handler("qqic", &getqqic, (void *)0);	add_read_handler("qrv", &getqrv, (void *)0);}

CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPq)
