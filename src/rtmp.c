#include "rtmp.d.h"

#include "amf.h"
#include "sgret.h"

int proc_rtmp(const u_char *data, int size)
{
	hdr_fmt* fmt = (hdr_fmt*) data;
	u_char * tmp = fmt;
	if(fmt->fmt == 1)
	{
		msg_type1* mhdr = (msg_type1*)(data+1);
		int l = mhdr->len[0] << 16;
		l |= mhdr->len[1] << 8;
		l |= mhdr->len[2];
		if(mhdr->tid == 0x13)
		{
			return proc_amf_so((u_char*)(data+1+sizeof(msg_type1)),
					   size, l);
		}
		return NOT_AMF_SO;
	}
	else
	{
		return NOT_RTMP_TYPE1;
	}
}
