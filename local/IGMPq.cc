#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "IGMPq.hh"


CLICK_DECLS
IGMPq::IGMPq() : _t(this), _qqic(125), _qrv(IGMP_DEFQRV), _startup(IGMP_DEFQRV), _mask(htonl(0xFFFFFF00)), _mrc(100), _lmqi(10)
{}

IGMPq::~ IGMPq()
{}

unsigned int getQQI(unsigned int qqi)
{
	if( qqi >= 128 ) {
		uint8_t mant = 255 & 0x0F;
		uint8_t exp = (255 & 0x70) >> 4;
		qqi = (mant | 0x10) << (exp+3);
	}
	return qqi;
}

int IGMPq::configure(Vector<String> &conf, ErrorHandler *errh) {
	_t.initialize(this);

	if (cp_va_kparse(conf, this, errh, "IP", cpkP+cpkM, cpIPAddress, &_addr, "QQIC", cpkP, cpByte, &_qqic, "QRV", cpkP, cpByte, &_qrv, "MASK", cpkP, cpIPAddress, &_mask, "MRC", cpkP, cpByte, &_mrc, "LMQI", cpkP, cpByte, &_lmqi, cpEnd) < 0) return -1;
	unsigned int qqi = getQQI(_qqic);
	if( _qrv > 7 ) {
		_qrv = 0;
		_startup = 0;
		_t.schedule_after_msec(qqi*1000); //no startup because qrv = 0
	}
	else {
		_t.schedule_after_msec(qqi*250); //startup query interval, 1/4 of the QQIC as stated in 8.6
		_startup = _qrv;
	}
	unsigned int mrt = getQQI(_mrc);
	if( mrt >= qqi*10 ) _mrc = _qqic; //if max response time exceeds the limit, set it to _qqic
	unsigned int lmqi = getQQI(_lmqi);
	if( lmqi >= qqi*10 ) _lmqi = _qqic; //if LMQI exceeds the limit, set it to _qqic
	return 0;
}

void IGMPq::setGroupTimer(GrpRec &rec, const IPAddress &mcast)
{
	gTimerData* timerdata = new gTimerData();
	timerdata->me = this;
	timerdata->group = mcast;
	rec.gt = new Timer(&IGMPq::gHandleExpiry,timerdata);
	rec.gt->initialize(this);
	rec.gt->schedule_after_msec(_qrv*getQQI(_qqic)*1000+(getQQI(_mrc)*100));
}

void IGMPq::setSourceTimer(SrcRecRouter &rec, const IPAddress &mcast)
{
	sTimerData* timerdata = new sTimerData();
	timerdata->me = this;
	timerdata->group = mcast;
	timerdata->src = rec.src;
	rec.st = new Timer(&IGMPq::sHandleExpiry,timerdata);
	rec.st->initialize(this);
	rec.st->schedule_after_msec(_qrv*getQQI(_qqic)*1000+(getQQI(_mrc)*100));
}

Vector<SrcRecRouter> DiffSet(const Vector<SrcRecRouter> &a, const Vector<SrcRecRouter> &b)
{
	Vector<SrcRecRouter> diff;
	for( unsigned int i=0; i < a.size(); i++ ) {
		bool found = false;
		for( unsigned int j=0; j < b.size(); j++ ) {
			if( b[j].src == a[i].src ) {
				found = true;
				break;
			}
		}
		if( !found ) diff.push_back(a[i]);
	}
	return diff;
}

void IGMPq::push(int, Packet* p)
{
	//respond to leave reports with a group specific query -> done
	//also determine if the report came from the same interface -> done
	//receiving the multicast source (UDP) packets here too
	//must determine whether or not we must forward the multicast source
	//upon receiving join reports, we must start forwarding -> done
	//we should be dealing only with IGMP or multicast IP packets
	if( p->packet_type_anno() == 2 and p->ip_header() and p->ip_header()->ip_p == IP_PROTO_IGMP ) {
		//IGMP
		uint32_t subnet = _addr.addr() & _mask.addr();
		if( (p->ip_header()->ip_src.s_addr & _mask.addr()) == subnet ) {
			//meaning we're on the same interface
			unsigned int offset = 0;
			unsigned int nog = ntohs((*(uint16_t*)(p->data()+30)));
			for( unsigned int group=0; group < nog; group++ ) {
			
			IPAddress mcast((*(uint32_t*)(p->data()+36+offset)));
			uint16_t nos = ntohs((*(uint16_t*)(p->data()+34+offset)));
			Vector<SrcRecRouter> repsrc;
			for( unsigned int i=0; i < nos; i++ ) {
				SrcRecRouter srec;
				srec.src = IPAddress((*(uint32_t*)(p->data()+40+i*4+offset)));
				srec.st = NULL;
				repsrc.push_back(srec);
			}
			if( (*(p->data()+32+offset)) == 0x04 or (*(p->data()+32+offset)) == 0x02 ) {
			//mode is exclude or change to exclude
				GrpRec *gr = _gtf.findp(mcast);
				if( gr ) { //group is present...
					if( gr->inc ) { //changing from include to exclude
						gr->inc = false; //because at least 1 host is in exclude mode
						Vector<SrcRecRouter> diff = DiffSet(repsrc, gr->srcrecs);
						Vector<SrcRecRouter> diff2 = DiffSet(gr->srcrecs, repsrc);
						for( unsigned int i=0; i < diff.size(); i++ ) {
							gr->srcrecs.push_back(diff[i]);
						}
						for( unsigned int i=0; i < gr->srcrecs.size(); i++ ) {
							for( unsigned int j=0; j < diff2.size(); j++ ) {
								if( gr->srcrecs[i].src == diff2[j].src ) {
									if( gr->srcrecs[i].st ) {
										gr->srcrecs[i].st->clear();
										delete gr->srcrecs[i].st;
									}
									gr->srcrecs.erase(gr->srcrecs.begin()+i);
									i--;
									break;
								}
							}
						}
						if( gr->gt ) delete gr->gt; //shouldn't be the case though...
						setGroupTimer((*gr), mcast);
					} else { //mode is already exclude
						Vector<SrcRecRouter> diff = DiffSet(gr->srcrecs, repsrc);
						Vector<SrcRecRouter> diff2 = DiffSet(repsrc, gr->srcrecs);
						for( unsigned int i=0; i < diff2.size(); i++ ) {
							gr->srcrecs.push_back(diff2[i]);
						}
						for( unsigned int i=0; i < gr->srcrecs.size(); i++ ) {
							for( unsigned int j=0; j < diff2.size(); j++ ) {
								if( gr->srcrecs[i].src == diff2[j].src ) {
									if( gr->srcrecs[i].st ) {
										gr->srcrecs[i].st->schedule_after_msec(_qrv*getQQI(_qqic)*1000+(getQQI(_mrc)*100));
									} else {
										setSourceTimer(gr->srcrecs[i], mcast);
									}
									break;
								}
							}
							for( unsigned int j=0; j < diff.size(); j++ ) {
								if( gr->srcrecs[i].src == diff[j].src ) {
									if( gr->srcrecs[i].st ) {
										gr->srcrecs[i].st->clear();
										delete gr->srcrecs[i].st;
									}
									gr->srcrecs.erase(gr->srcrecs.begin()+i);
									i--;
									break;
								}
							}
						}
						gr->gt->schedule_after_msec(_qrv*getQQI(_qqic)*1000+(getQQI(_mrc)*100));
					}
				} else {
					GrpRec rec;
					rec.inc = false;
					rec.srcrecs = repsrc;
					setGroupTimer(rec, mcast);
					_gtf.insert(mcast, rec);
				}
			}
			else if( (*(p->data()+32+offset)) == 0x03 or (*(p->data()+32+offset)) == 0x01 ) {
			//mode is include or change to include
				GrpRec *gr = _gtf.findp(mcast);
				if( gr and nos > 0 ) { //group record should always be present... else add it
					//same stuff needs to be done for both include & exclude mode
					for( unsigned int i=0; i < repsrc.size(); i++ ) {
						bool found = false;
						for( unsigned int j=0; j < gr->srcrecs.size(); j++ ) {
							if( gr->srcrecs[j].src == repsrc[i].src ) {
								found = true;
								if( gr->srcrecs[j].st ) {
									gr->srcrecs[j].st->schedule_after_msec(_qrv*getQQI(_qqic)*1000+(_mrc*100));
								} else {
									setSourceTimer(gr->srcrecs[j], mcast);
								}
								break;
							}
						}
						if( !found ) {
							gr->srcrecs.push_back(repsrc[i]);
							setSourceTimer(gr->srcrecs.back(), mcast);
						}
					}
				} else if( !gr and nos > 0 ) {
					GrpRec rec;
					rec.inc = true;
					for( unsigned int i=0; i < nos; i++ ) {
						SrcRecRouter srec;
						srec.src = IPAddress((*(uint32_t*)(p->data()+40+i*4+offset)));
						setSourceTimer(srec, mcast);
						rec.srcrecs.push_back(srec);
					}
					rec.gt = NULL;
					_gtf.insert(mcast, rec);
				}
				//generate IP header for group specific query and group specific query itself...
				if( nos == 0 and (*(p->data()+32+offset)) == 0x03 ) {
				//only need a group specific query if it is a leave report
					GSDelayData* gsddata = new GSDelayData();
					gsddata->mcast = mcast;
					gsddata->me = this;
					Timer* t = new Timer(&IGMPq::handleGSDelay,gsddata);
					t->initialize(this);
					t->schedule_after_msec(0);
					//delays the group specific query just enough for the right "dumping" order
				}
			}
			offset = offset + 8 + 4*nos;
			}
		}
	}
	else if( p->ip_header() and p->dst_ip_anno().is_multicast() ) {
		//multicast source
		IPAddress src(p->ip_header()->ip_src);
		IPAddress mcast(p->ip_header()->ip_dst);
		GrpRec *gr = _gtf.findp(mcast);
		if( gr ) { //group is present...
			bool found = false;
			for( unsigned int i=0; i < gr->srcrecs.size(); i++ ) {
				if( src == gr->srcrecs[i].src ) {
					found = true;
					if( gr->srcrecs[i].st and !gr->inc ) found = false;
					break;
				}
			}
			if( (gr->inc and found) or (!gr->inc and !found) ) {
				output(0).push(p);
				return;
			}
		}
	}
	//else nothing?
}

void IGMPq::gHandleExpiry(Timer* t, void * data){
	gTimerData * timerdata = (gTimerData*) data;
	assert(timerdata); // the cast must be good
	timerdata->me->GroupExpire(timerdata);
	delete t;
}

void IGMPq::GroupExpire(gTimerData * tdata){
	GrpRec *gr = tdata->me->_gtf.findp(tdata->group);
	if( gr ) {
		gr->inc = true;
		gr->gt = NULL; //mem is freed in gHandleExpiry
		for( unsigned int i=0; i < gr->srcrecs.size(); i++ ) {
			if( !gr->srcrecs[i].st ) {
				gr->srcrecs.erase(gr->srcrecs.begin()+i);
				i--;
			}
		}
		if( gr->srcrecs.size() == 0 ) tdata->me->_gtf.erase(tdata->group);
	}
	delete tdata;
}

void IGMPq::sHandleExpiry(Timer* t, void * data){
	sTimerData * timerdata = (sTimerData*) data;
	assert(timerdata); // the cast must be good
	timerdata->me->SourceExpire(timerdata);
	delete t;
}

void IGMPq::SourceExpire(sTimerData * tdata){
	GrpRec *gr = tdata->me->_gtf.findp(tdata->group);
	if( gr ) {
		if( gr->inc ) {
			//Suggest to stop forwarding traffic from source and remove source record.
			//If there are no more source records for the group, delete group record.
			for( unsigned int j=0; j < gr->srcrecs.size(); j++ ) {
				if( gr->srcrecs[j].src == tdata->src ) {
					gr->srcrecs.erase(gr->srcrecs.begin()+j);
					break;
				}
			}
			if( gr->srcrecs.size() == 0 ) {
				if( gr->gt ) delete gr->gt; //shouldn't be possible but just to be safe
				tdata->me->_gtf.erase(tdata->group);
			}
		} else {
			//Suggest to not forward traffic from source (DO NOT remove record)
			for( unsigned int j=0; j < gr->srcrecs.size(); j++ ) {
				if( gr->srcrecs[j].src == tdata->src ) {
					gr->srcrecs[j].st = NULL; //mem is freed in sHandleExpiry
					break;
				}
			}
		}
	}
	delete tdata;
}


void IGMPq::handleGSDelay(Timer* t, void * data){
	GSDelayData * timerdata = (GSDelayData*) data;
	assert(timerdata); // the cast must be good
	timerdata->me->GSDelay(timerdata);
	delete t;
}

void IGMPq::GSDelay(GSDelayData * timerdata){
	//timerdata->me->_gtf.erase(timerdata->mcast); //temporarily to stop forwarding, need expiration timers
	GrpRec *gr = timerdata->me->_gtf.findp(timerdata->mcast);
	if( gr and gr->gt ) {
		unsigned int lmqt = timerdata->me->_qrv*getQQI(timerdata->me->_lmqi)*100;
		if( (gr->gt->expiry() - Timestamp::now())*1000 > lmqt )
			gr->gt->schedule_after_msec(lmqt);
		for( unsigned int i=0; i < gr->srcrecs.size(); i++ ) {
			if( gr->srcrecs[i].st and (gr->srcrecs[i].st->expiry() - Timestamp::now())*1000 > lmqt)
				gr->srcrecs[i].st->schedule_after_msec(lmqt);
		}
	}
	Packet* q = generateGroupSpecificQuery(timerdata->mcast);
	output(1).push(q);
	delete timerdata;
}

//generates general queries
void IGMPq::run_timer(Timer* t){
	igmpv3_query data;
	data.type = IGMP_QUERY;
	data.mrc = _mrc;
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

	unsigned int qqi = getQQI(_qqic);
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
	data.mrc = _lmqi;
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
{
	IGMPq * me = (IGMPq *) e;
	uint32_t qqic = 125;
	if(cp_va_kparse(conf, me, errh, "QQIC", cpkP, cpUnsigned, &qqic, cpEnd) < 0) return -1;
	if( qqic > 255 ) me->_qqic = 255; //QQIC is 1 byte (unsigned), so top off at 255
	else me->_qqic = qqic;
	unsigned int qqi = getQQI(me->_qqic);
	unsigned int mrt = getQQI(me->_mrc);
	if( mrt >= qqi*10 ) me->_mrc = me->_qqic; //if max response time exceeds the limit, set it to _qqic
	unsigned int lmqii = getQQI(me->_lmqi);
	if( lmqii >= qqi*10 ) me->_lmqi = me->_qqic; //if LMQI exceeds the limit, set it to _qqic
	return 0;
}

//If no parameter is specified, we use the default value of 2
int IGMPq::setqrv(const String &conf, Element *e, void * thunk, ErrorHandler * errh)
{
	IGMPq * me = (IGMPq *) e;
	uint32_t qrv = IGMP_DEFQRV;
	if(cp_va_kparse(conf, me, errh, "QRV", cpkP, cpUnsigned, &qrv, cpEnd) < 0) return -1;
	if( qrv > 7 ) me->_qrv = 0;
	else me->_qrv = qrv;
	return 0;
}

//If no parameter is specified, we use the default value of 100 or less than QQIC
int IGMPq::setmrc(const String &conf, Element *e, void * thunk, ErrorHandler * errh)
{
	IGMPq * me = (IGMPq *) e;
	uint32_t mrc = 100;
	if(cp_va_kparse(conf, me, errh, "MRC", cpkP, cpUnsigned, &mrc, cpEnd) < 0) return -1;
	if( mrc > 255 ) me->_mrc = 255; //MRC is 1 byte (unsigned), so top off at 255
	else me->_mrc = mrc;
	unsigned int qqi = getQQI(me->_qqic);
	unsigned int mrt = getQQI(me->_mrc);
	if( mrt >= qqi*10 ) me->_mrc = me->_qqic; //if max response time exceeds the limit, set it to _qqic
	return 0;
}

//If no parameter is specified, we use the default value of 10 or less than QQIC
int IGMPq::setlmqi(const String &conf, Element *e, void * thunk, ErrorHandler * errh)
{
	IGMPq * me = (IGMPq *) e;
	uint32_t lmqi = 100;
	if(cp_va_kparse(conf, me, errh, "LMQI", cpkP, cpUnsigned, &lmqi, cpEnd) < 0) return -1;
	if( lmqi > 255 ) me->_lmqi = 255; //LMQI has to fit in MRC so is 1 byte (unsigned), top off at 255
	else me->_lmqi = lmqi;
	unsigned int qqi = getQQI(me->_qqic);
	unsigned int lmqii = getQQI(me->_lmqi);
	if( lmqii >= qqi*10 ) me->_lmqi = me->_qqic; //if LMQI exceeds the limit, set it to _qqic
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

String IGMPq::getmrc(Element *e, void * thunk)
{
	IGMPq *me = (IGMPq *) e;
	String mrc((int)(me->_mrc));
	mrc += "\n";
	return mrc;
}

String IGMPq::getlmqi(Element *e, void * thunk)
{
	IGMPq *me = (IGMPq *) e;
	String lmqi((int)(me->_lmqi));
	lmqi += "\n";
	return lmqi;
}

String IGMPq::getinfo(Element *e, void * thunk)
{
	IGMPq *me = (IGMPq *) e;
	String info;
	IPAddress subnet(me->_addr.addr() & me->_mask.addr());
	info += "\nIGMP State for " + subnet.unparse() + "/24 network :\n\n";
	for( HashMap<IPAddress, GrpRec>::iterator it = me->_gtf.begin(); it != me->_gtf.end(); ++it ) {
		info += "Group timer for " + it.key().unparse();
		if( it.value().gt ) {
			info += " is scheduled in " + (it.value().gt->expiry() - Timestamp::now()).unparse();
			info += " seconds ";
		} else info += " has expired ";
		if( it.value().inc ) info += "(include mode).\n";
		else info += "(exlude mode).\n";
		for( unsigned int i=0; i < it.value().srcrecs.size(); i++ ) {
			info += "\tSource timer for " + it.value().srcrecs[i].src.unparse();
			if( it.value().srcrecs[i].st ) {
				info += " is scheduled in ";
				info += (it.value().srcrecs[i].st->expiry() - Timestamp::now()).unparse();
				info += " seconds.\n";
			} else info += " has expired.\n";
		}
	}
	info += "\n";
	return info;
}

void IGMPq::add_handlers()
{
	add_write_handler("qqic", &setqqic, (void *)0);
	add_write_handler("qrv", &setqrv, (void *)0);
	add_write_handler("mrc", &setmrc, (void *)0);
	add_write_handler("lmqi", &setlmqi, (void *)0);
	add_read_handler("qqic", &getqqic, (void *)0);
	add_read_handler("qrv", &getqrv, (void *)0);
	add_read_handler("mrc", &getmrc, (void *)0);
	add_read_handler("lmqi", &getlmqi, (void *)0);
	add_read_handler("info", &getinfo, (void *)0);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IGMPq)
