#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "amf.d.h"

/* get the lenth from an amf_type, data[0] must belong to length */
static int amf_getl(const uint8_t *data)
{
	uint16_t _l = (uint16_t)(data[0]) << 8;
	_l |= (uint16_t) data[1];
	return _l;
}

/* create a new string from src, and copy n elements*/
static uint8_t *amfstrcpy(const uint8_t *src, int n)
{
	uint8_t *buf = malloc(n + 1);
	strncpy((char *)buf, (const char *)src, n);
	buf[n] = 0;
#ifdef DEBUG_BUILD
	wprintf(L"cpy:%s\n", buf);
#endif
	return buf;
}

static amf_name *get_amfname(const uint8_t *data)
{
	amf_name *buf = malloc(sizeof(amf_name));
	buf->len = amf_getl((const uint8_t *)data);
#ifdef DEBUG_BUILD
	wprintf(L"name.l:%x\n", buf->len);
#endif
	buf->txt = amfstrcpy((data + 2), buf->len);
	return buf;
}
static int proc_msg(const uint8_t *data, uint8_t *id, int size)
{
	amf_str *msg = malloc(sizeof(amf_str));
	msg->len = amf_getl((data + 1));
	msg->txt = amfstrcpy((data + 3), msg->len);
#if defined DEBUG_BUILD || defined PRINT_MSG_ONLY
	wprintf(L"proc'd msg: %s %x\n", msg->txt, msg->len);
#endif
	free(msg->txt);
	free(msg);
	return MSG_PROCD;
}

int proc_amft(const uint8_t *data, int size)
{
	/* get the id offset */
	uint16_t idoff = amf_getl(data) + 2;
	/* get the id */
	amf_name *id = get_amfname(data + idoff + 17);

	if(id->txt[0] == 'd')
	{
		int _t  = proc_msg((const uint8_t *)(data + idoff + 17 + id->len + 2), ((id)->txt + 1), 0);
		free(id->txt);
		free(id);
		return _t;
	}
	return -1;
}
