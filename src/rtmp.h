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

/* function defs */
static inline int proc_rtype1(const uint8_t* data)
{
	cmsg_type1* hdr = (cmsg_type1*)data;
	uint32_t l = hdr->l[0] << 16;
	l |= (hdr->l[1] << 8);
	l |= (hdr->l[2]);
#ifdef DEBUG_BUILD
	wprintf(L"%.2x %2x %2x %2x\n", l, hdr->l[0], hdr->l[1], hdr->l[2]);
#endif
	/* amf0 shared object */
	if (hdr->tid == 0x13)
	{
		return proc_amft(data+sizeof(cmsg_type1), l);
	}
	return NOT_AMF_SO;
}

static inline int proc_rtmp1(const uint8_t* data)
{
	cb_hdr_1* hdr = (cb_hdr_1*)data;
#ifdef DEBUG_BUILD
	wprintf(L"%x:%d\n", hdr->fmt, hdr->fmt);
#endif
	if(hdr->fmt == 1)
	{
		return proc_rtype1((data+sizeof(cb_hdr_1)));
	}
	return NOT_TYPE_1;
}
#endif