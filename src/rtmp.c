

#include "sg.d.h"

#include "amf.h"

static int proc_rtype1(const uint8_t *data)
{
	cmsg_type1 *hdr = (cmsg_type1 *)data;
	uint32_t l = hdr->l[0] << 16;
	l |= (hdr->l[1] << 8);
	l |= (hdr->l[2]);
#ifdef DEBUG_BUILD
	wprintf(L"%.2x %2x %2x %2x\n", l, hdr->l[0], hdr->l[1], hdr->l[2]);
#endif
	/* amf0 shared object */
	if(hdr->tid == 0x13)
	{
		return proc_amft((data + sizeof(cmsg_type1)), l);
	}
	return NOT_AMF_SO;
}

int proc_rtmp(const uint8_t *data, int size)
{
	cb_hdr_1 *hdr = (cb_hdr_1 *)data;
#ifdef DEBUG_BUILD
	wprintf(L"%x:%d\n", hdr->fmt, hdr->fmt);
#endif
	if(hdr->fmt == 1)
	{
		return proc_rtype1((data + sizeof(cb_hdr_1)));
	}
	return NOT_TYPE_1;
}
