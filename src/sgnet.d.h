#ifndef SG_NET_D_H
#define SG_NET_D_H

#include <stdint.h>

typedef struct
{
	uint8_t dest[6];
	uint8_t src[6];
	uint16_t type;
} eth_hdr;

typedef struct
{
	uint8_t hl: 4;
	uint8_t v: 4;
	uint8_t tos;
	uint16_t len;
	uint16_t id;
	uint16_t off;
#define	IP_RF 0x8000
#define	IP_DF 0x4000
#define	IP_MF 0x2000
#define	IP_OFFMASK 0x1fff
	uint8_t ttl;
	uint8_t prot;
	uint16_t csum;
	uint32_t src;
	uint32_t dest;
} ip_hdr;

typedef struct
{
	uint16_t src;
	uint16_t dst;
	uint32_t seq;
	uint32_t ack_seq;
	uint8_t ns:1;
	uint8_t res:3;
	uint8_t doff:4;
	uint8_t fin:1;
	uint8_t syn:1;
	uint8_t rst:1;
	uint8_t psh:1;
	uint8_t ack:1;
	uint8_t urg:1;
	uint8_t ecn:1;
	uint8_t cwr:1;
} tcp_hdr;

#endif
