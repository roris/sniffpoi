#define _BSD_SOURCE	1
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

#ifndef SG_BUFSZ
#define SG_BUFSZ	65535
#endif

#ifndef  SG_TIMEOUT
#define SG_TIMEOUT	1000
#endif

static struct bpf_program bpfp;
static pcap_t *handle;
static struct pcap_pkthdr *pcap_hdr;
static u_char *pkt_data;

#include "sgerr.h"
#include "sgf.h"
#include "sgnet.h"

static void sg_sighndlr()
{
	if(!sgf.lctl) exit(EXIT_SUCCESS);
	sgf.lctl = 0;
}

void sg_cleanup(void)
{
	printf("\n------cleaning up------\n");
	if(sgf.comp)
	{
		printf("freeing compiled filter\n");
		pcap_freecode(&bpfp);
		sgf.comp = 0;
	}
	if(handle)
	{
		printf("ending sniffing session\n");
		pcap_close(handle);
		handle = NULL;
	}
	printf("-----------------------\n");
}


int sg_init(void)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *devs, *dev;

	if(pcap_findalldevs(&devs, errbuf))
	{
		sg_err("Failed to retrieve the device list: %s\n", errbuf);
		return -1;
	}
	int i = 0, ndev;
	for(dev = devs; dev; dev = dev->next)
	{
		printf("%d.%s", ++i, dev->name);
		if(dev->description) printf(" (%s)\n", dev->description);
		else printf(" (No description available)\n");
	}
	if(!i)
	{
		sg_err("No devices found!\n");
		return -1;
	}
	printf("Enter the interface number: ");
	fscanf(stdin, "%d", &ndev);

	if(ndev < 0 || ndev > i)
	{
		sg_err("Out of range.\n");
		pcap_freealldevs(devs);
		return -1;
	}

	for(dev = devs, i = 0; i < ndev - 1; dev = dev->next, i++);

	if((handle = pcap_open_live(dev->name, SG_BUFSZ, 1, SG_TIMEOUT, errbuf
				   )) == NULL)
	{
		sg_err("Couldn't open device %s: %s\n", dev->name, errbuf);
		pcap_freealldevs(devs);
		return -2;
	}
	printf("Opened %s\n", dev->name);

	/* point of no return */
	atexit(sg_cleanup);
	signal(SIGINT, sg_sighndlr);
	signal(SIGTERM, sg_sighndlr);

	/* compile and set filter */
	if(pcap_compile(handle, &bpfp,
			"src 111.102.245.226",
			0, 0))
	{
		sg_err("Couldn't parse filter: %s", pcap_geterr(handle));
		return -2;
	}
	sgf.comp = 1;

	if(pcap_setfilter(handle, &bpfp))
	{
		sg_err("Couldn't install filter: %s",
		       pcap_geterr(handle));
		return -3;
	}
	return 0;
}

int sg_sniff(void)
{
	u_int res;
	sgf.lctl = 1;
	while((res = pcap_next_ex(handle, &pcap_hdr, &pkt_data
				 )) >= 0 && sgf.lctl)
	{
		if(!res) continue;
#ifdef DEBUG_BUILD
		printf("captured\n");
#endif
		proc_pkt(pkt_data, pcap_hdr->caplen);
	}
	if(res == -1)
	{
		sg_err("Error reading packet: %s\n", pcap_geterr(handle));
		return res;
	}
	return 0;
}

