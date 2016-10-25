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
    uint32_t	gaddr;			/* 4-7   group address		     */
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

#endif
