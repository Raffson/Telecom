#ifndef CLICK_IGMPV3_HH
#define CLICK_IGMPV3_HH

/*
 * <igmpv3.hh> -- IGMPv3 header definitions.
 *
 * Relevant RFCs include:
 *   RFC3376	Internet Group Management Protocol version 3
 */

struct igmpv3_query {
    uint8_t	type;			/* 0     for query 0x11		     */
#define IGMP_QUERY	0x11		/*       code for IGMP query	     */
    uint8_t	mrc;			/* 1     max response code	     */
    uint16_t	sum;			/* 2-3   checksum		     */
    uint32_t	mcaddr;			/* 4-7   Multicast Address	     */
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
    unsigned	resv : 4;		/* 8     Reserved field		     */
    unsigned	s : 1;			/*       S flag			     */
    unsigned	qrv : 3;		/*       Querier's Robustness Var    */
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
    unsigned	qrv : 3;		/*       Querier's Robustness Var    */
    unsigned	s : 1;			/*       S flag			     */
    unsigned	resv : 4;		/* 8     Reserved field		     */
#else
#   error "unknown byte order"
#endif
#define	IGMP_DEFQRV	0x2		/*       Default QRV		     */
    uint8_t	qqic;			/* 9  Querier's Query Inverval Code  */
#define	IGMP_DEFQQIC	0x7D		/*       Default QQIC		     */
    uint16_t	nos;			/* 10-11 Number of Sources	     */
};

struct igmpv3_report {
    uint8_t	type;			/* 0     for report 0x22	     */
#define IGMP_REPORT	0x22		/*       code for IGMP report	     */
    uint8_t	reserved1;		/* 1     1st reserved field 	     */
    uint16_t	sum;			/* 2-3   checksum		     */
    uint16_t	reserved2;		/* 4-5   2nd reserved field	     */
    uint16_t	nogr;			/* 6-7   number of group records     */
};

struct igmpv3_grecord {
    uint8_t	rtype;			/* 0     for query 0x11		     */
#define IGMP_MODE_IS_INCLUDE	0x01	/*     code for IGMP MODE_IS_INCLUDE */
#define IGMP_MODE_IS_EXCLUDE	0x02	/*     code for IGMP MODE_IS_EXCLUDE */
#define IGMP_CHANGE_TO_INCLUDE	0x03	/*   code for IGMP CHANGE_TO_INCLUDE */
#define IGMP_CHANGE_TO_EXCLUDE	0x04	/*   code for IGMP CHANGE_TO_EXCLUDE */
    uint8_t	adl;			/* 1     Aux Data Length 	     */
    uint16_t	nos;			/* 2-3   Number of Sources	     */
    uint32_t	mcaddr;			/* 4-7   Multicast Address	     */
};

//what about auxiliary data & sources?

#endif
