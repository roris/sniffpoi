#ifndef AMF_H
#define AMF_H

#include <stdlib.h>

#ifdef WIN32
#include <Winsock2.h>
#else
#include <netinet/in.h>
#include <string.h>
#endif

#include "sg.d.h"

typedef struct
{
	uint16_t l;
	uint8_t *txt;
} amf_name;

typedef struct
{
	uint8_t type;
	uint16_t l;
	uint8_t *txt;
} amf_str;

typedef struct
{
	uint8_t type;
	uint64_t val;
} amf_num;

typedef struct
{
	uint8_t type;
} amf_nul;

/* function defs */

static inline int amf_getl(const uint8_t *data)
{
	uint16_t *l = data;
	return ntohs(*l);
}

/* create a new string, and copy */
static inline uint8_t* amfstrcpy(const uint8_t* src, int n)
{
	uint8_t* dest = malloc(n+1);
	strncpy(dest, src, n);
	dest[n] = 0;
#ifdef DEBUG_BUILD
	wprintf(L"cpy:%s\n", dest);
#endif
	return dest;
}

static inline amf_name *get_amfname(const uint8_t *data)
{
	amf_name *buf = malloc(sizeof(amf_name));
	buf->l = amf_getl(data);
#ifdef DEBUG_BUILD
	wprintf(L"name.l:%x\n", buf->l);
#endif
	buf->txt = amfstrcpy(data+2, buf->l);
	return buf;
}

static inline int proc_msg(const uint8_t *data, uint8_t *id, int size)
{
	amf_str* str = malloc(sizeof(amf_str));
	str->l = amf_getl(data+1);
	str->txt = amfstrcpy(data+3, str->l);
#ifdef DEBUG_BUILD
	wprintf(L"proc'd msg: %s %x\n", str->txt, str->l);
#endif
	free(str->txt);
	free(str);
	return MSG_PROCD;
}

static inline int proc_amft(const uint8_t *data, int size)
{
	/* get the id offset */
	uint16_t idoff = amf_getl(data) + 2;
	/* get the id */
	amf_name *id = get_amfname(data + idoff + 17);
	if(id->txt[0] == 'd')
	{
		int _t  = proc_msg((data + idoff +17 +id->l + 2), ((id)->txt + 1), 0);
		free(id->txt);
		free(id);
		return _t;
	}
	return -1;
}
#endif

