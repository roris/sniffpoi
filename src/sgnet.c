#include <stdio.h>

#include "sgnet.d.h"
#include "rtmp.h"
#include "sgret.h"
#include "sgerr.h"

int proc_pkt(const u_char *pkt_data, int size)
{
	ip4_hdr *ih = (ip4_hdr *)(pkt_data + 14);
	int iplen = ih->ihl * 4;

	if(iplen < 20)
	{
		sg_err("Invalid IP header length\n");
		return INVALID_IP_HDR_LEN;
	}

	tcp_hdr *th = (tcp_hdr *)(pkt_data + 14 + iplen);
	int tcplen = (th->doff) * 4;

	if(tcplen < 20)
	{
		sg_err("Invalid TCP header length: %d\n", tcplen);
		return INVALID_TCP_HDR_LEN;
	}

	/* if(th->fin) sg_end();
	if(th->rst || th->syn) restart(); */

	int datasize = size - (tcplen + iplen + 14);
	if(datasize <= 0) return EMPTY_PACKET;
	return proc_rtmp((u_char *)(pkt_data + iplen + 14 + tcplen), datasize);
}
