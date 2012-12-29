#ifndef SG_NET_D_H
#define SG_NET_D_H

#include "sgint.h"

typedef struct
{
	uint ihl: 4;
	uint ver: 4;
	uint8 tos;
	uint16 len;
	uint16 id;
	uint16 off;
	uint8 ttl;
	uint8 prot;
	uint16 csum;
	uint32 src;
	uint32 dest;
} ip4_hdr;

typedef struct
{
	uint16 src;
	uint16 dst;
	uint32 seq;
	uint32 ack_seq;
	uint ns:1;
	uint res:3;
	uint doff:4;
	uint fin:1;
	uint syn:1;
	uint rst:1;
	uint psh:1;
	uint ack:1;
	uint urg:1;
	uint ecn:1;
	uint cwr:1;
} tcp_hdr;
#endif
