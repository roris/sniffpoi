#define _BSD_SOURCE 1

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>

#include <pcap.h>

#include "rtmp.h"
#include "sgnet.d.h"

#include "sgerr.h"

/* you might want to adjust/define these two*/
#ifndef SNAP_MAX_LEN
#define SNAP_MAX_LEN	BUFSIZ
#endif
#ifndef SG_TIMEOUT
#define SG_TIMEOUT	1000
#endif

static uint8_t fci; 	/* filter compilation indicator */
static struct bpf_program bpfp;
static pcap_t *handle;
static bpf_u_int32 netp, maskp;
static const char *fexp = "src 111.102.245.226";
static struct pcap_pkthdr *pcap_hdr;

static u_char *pkt_data;

int sg_lctl; /* loop control */

/* signal handler for sigint, sigterm */
static void sg_sighndlr()
{
	if(!sg_lctl) exit(EXIT_SUCCESS);
	/* sigint or term to break from loop */
	sg_lctl = 0;
}

void sg_cleanup()
{
	wprintf(L"\n------cleaning up------\n");
	if(fci)
	{
		wprintf(L"freeing compiled filter\n");
		pcap_freecode(&bpfp);
		fci = 0;
	}
	if(netp) netp = 0, maskp = 0;
	if(handle)
	{
		wprintf(L"ending sniffing session\n");
		pcap_close(handle);
		handle = NULL;
	}
	wprintf(L"-----------------------\n");
}

int sg_init()
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];

	/* get the device */
	if((dev = pcap_lookupdev(errbuf)) == NULL)
	{
		sg_err(L"Couldn't find default device: %s\n", errbuf);
		return -1;
	}

	/* get mask/network number */
	if(pcap_lookupnet(dev, &netp, &maskp, errbuf))
	{
		sg_err(L"Couldn't get netmask for device: %s\n", errbuf);
		netp = 0;
		maskp = 0;
		return -1;
	}

	/* get the handle for the session */
	if((handle = pcap_open_live(dev, SNAP_MAX_LEN, 1, SG_TIMEOUT, errbuf)) 
		== NULL)
	{
		sg_err(L"Couldn't open device %s: %s\n", dev, errbuf);
		return -2;
	}

	/* point of no return */
	atexit(sg_cleanup);
	signal(SIGINT, sg_sighndlr);
	signal(SIGTERM, sg_sighndlr);

	/* compile and set filter */
	if(pcap_compile(handle, &bpfp, fexp, 0, netp))
	{
		sg_err(L"Couldn't parse filter %s: %s", fexp,
		       pcap_geterr(handle));
		return -2;
	}
	fci = 1;

	if(pcap_setfilter(handle, &bpfp))
	{
		sg_err(L"Couldn't install filter %s: %s",
		       fexp, pcap_geterr(handle));
		return -3;
	}
	return 0;
}


static inline int proc_payload(const u_char *data, int off, int size)
{
	int datalen = size - off;
	if(datalen <= 0)
	{
		wprintf(L"Empty packet\n");
		return 0;
	}
	/* get the rtmp header here */
#ifdef DEBUG_BUILD
	wprintf(L"proc_packet\n");
#endif
	proc_rtmp1(data);
}

static inline int proc_tcp(const u_char *data, int off,int size)
{
	tcp_hdr *tcp = (tcp_hdr *)(data);
	int tcplen = (tcp->doff) * 4;
	if(tcplen < 20)
	{
		sg_err(L"Invalid TCP header length: %u", tcplen);
		return INVALID_TCP_HEADER_LENGTH;
	}
	return proc_payload((data + tcplen), tcplen, size);
}

static inline int proc_ip4(const u_char *data, int size)
{
	int iplen;
	ip_hdr *ip = (ip_hdr *)(data);
	iplen = ip->hl * 4;
	if(iplen < 20)
	{
		sg_err(L"Invalid IP header length: %u", iplen);
		return INVALID_IP_HEADER_LENGTH;
	}
	switch(ip->prot)
	{
	case 6:
#ifdef DEBUG_BUILD
		wprintf(L"tcp\n");
#endif
		return proc_tcp((data + iplen), iplen,size);
	default:
		return TRANSPORT_PROTOCOL_NOT_SUPPORTED;
	}
}

static inline int proc_eth(const u_char *data, int size)
{
	eth_hdr *eth = (eth_hdr *)(data);
	if(ntohs(eth->type) == 0x0800)
	{
#ifdef DEBUG_BUILD
		wprintf(L"ipv4\n");
#endif
		return proc_ip4((data + sizeof(eth_hdr)), size);
	}
	/* not ipv4 */
	else return INTERNET_PROTOCOL_NOT_SUPPORTED;
}

int sg_sniff()
{
	u_int res;
	sg_lctl = 1;
	while((res = pcap_next_ex(handle, &pcap_hdr, &pkt_data)) >= 0 && sg_lctl)
	{
		if(!res) continue;
#ifdef DEBUG_BUILD
		wprintf(L"captured!!\n");
#endif
		proc_eth(pkt_data, pcap_hdr->caplen);
	}
	if(res == -1)
	{
		sg_err(L"Error reading packet: %s\n", pcap_geterr(handle));
		return res;
	}
	return 0;
}

/*int main(void)
{
	if(sg_init()) return 1;
	sg_sniff();
}*/


