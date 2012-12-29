#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "amf.d.h"
#include "sgret.h"

static uint16 get_len(const u_char *data)
{
	uint16 l = data[0] << 8;
	l |= data[1];
	printf("get_len: %x\n", l);
	return l;
}

static u_char *get_str(const u_char *src, int n)
{
	u_char *buf = malloc(n + 1);
	strncpy((char *)buf, (char *)src, n);
	buf[n] = 0;
	printf("get_str(%u):%s\n", n, buf);
	return buf;
}

static amf_name *new_amf_name(const u_char *data)
{
	amf_name *buf = malloc(sizeof(amf_name));
	buf->l = get_len(data);
	buf->txt = get_str(data + 2, buf->l);
	printf("new_amf_name(): %u %s\n", buf->l, buf->txt);
	return buf;
}

static int proc_msg(const u_char *data, u_char *id, int size)
{
	amf_str *buf = malloc(sizeof(amf_str));
	buf->val.l = get_len(data + 1);
	/* TODO:Bounds check, if string doesn't fit in size, make size the
	 * current length, set wait flag and then cache the string.
	 */
	buf->val.txt = get_str(data + 3, buf->val.l);
	printf("proc_msg: (%s): %s\n", id, buf->val.txt);
	free(buf->val.txt);
	free(buf);
	return MSG_PROCD;
}

int proc_amf_so(const u_char *data, int size, int chunklength)
{
	printf("proc_amf_so()\n");
	uint shareloc = get_len(data) + 2;
	amf_name *id = new_amf_name(data + shareloc + 17);
	int ret;
	if(id->txt[0] == 'd')
		ret = proc_msg((const u_char *)(data + shareloc + 17 + id->l + 2),
			       (id->txt + 1), size);
	else ret = NOT_MSG;
	free(id->txt);
	free(id);
	return ret;
}
