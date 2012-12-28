#ifndef SG_RTMP_H
#define SG_RTMP_H

#include <stdint.h>

#ifdef DEBUG_BUILD
#include <wchar.h>
#endif

#include "amf.h"

/* struct defs */
typedef struct
{
	uint8_t cid: 6;
	uint8_t fmt: 2;
} cb_hdr_1;
typedef struct
{
	uint8_t _0: 6;
	uint8_t fmt: 2;
	uint8_t cid_64;
} cb_hdr_2;
typedef struct
{
	uint8_t _1: 6;
	uint8_t fmt: 2;
	uint16_t cid_64;
} cb_hdr_3;
typedef struct
{
	uint8_t ts[3];
	uint8_t l[3];
	uint8_t tid;
	uint32_t sid;
} cmsg_type0;
typedef struct
{
	uint8_t ts_delta[3];
	uint8_t l[3];
	uint8_t tid;
} cmsg_type1;
typedef struct
{
	uint8_t ts_delta[3];
} cmsg_type2;
/*  \struct defs */

#endif
