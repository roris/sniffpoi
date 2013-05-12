#define _BSD_SOURCE	1

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>

typedef unsigned int uint;

static void sg_cleanup ( void );
static void sg_sigh();

struct ip4h
{
	uint ihl: 4;
	uint ver: 4;
	uint8_t tos;
	uint16_t len;
	uint16_t id;
	uint16_t off;
	uint8_t ttl;
	uint8_t prot;
	uint16_t csum;
	uint32_t src;
	uint32_t dest;
};

struct tcph
{
	uint16_t src;
	uint16_t dst;
	uint32_t seq;
	uint32_t ack_seq;
	uint ns:1;
	uint res:3;
	uint doff:4;
	uint fin:1;
	uint syn:1;
	uint rst:1;
	uint psh:1;
	uint ack:1;
	uint urg:1;
	uint ecn:1;
	uint cwr:1;
};

struct hdr_fmt
{
	uint _0:6;
	uint fmt:2;
};

struct msgt1
{
	uint8_t ts_delta[3];
	uint8_t len[3];
	uint8_t tid;
};

static struct bpf_program bpfp;
static pcap_t *handle;
volatile static uint8_t sgf;
static char* id;

struct server
{
	int port;
	FILE *logfile;
	struct user *usrs;
	struct server *next;
};

struct user
{
	char *id;
	char *name;
	struct user *next;
};

#define SGF_SET(b)		(sgf |= b)
#define SGF_ISSET(b)		(sgf & b)
#define SGF_OFF(b)		(sgf &= ~(b))
#define SGF_FILTER		0x01
#define SGF_LCTL		0x02

#define ETHLEN			14

#define SG_FILTER_EXP		"src 111.102.245.226"
#define SG_BUFSZ		65535
#define SG_TIMEOUT		1000
#define SG_ID_SIZE		10

#define ERRPRINT(...)		fprintf(stderr,__VA_ARGS__)

int
main ( void )
{

	char errbuf[PCAP_ERRBUF_SIZE];
	int i, n, offset;
	pcap_if_t *devs, *dev;
	void *x;
	struct pcap_pkthdr * pcap_hdr;
	u_char *pkt_data;

	if ( pcap_findalldevs ( &devs, errbuf ) )
	{
		ERRPRINT ( "Failed to retrieve the device list: %s\n", errbuf );
		return EXIT_FAILURE;
	}

	for ( dev = devs, i = 0; dev; dev = dev->next )
	{
		printf ( "%d.%s", i++, dev->name );
		if ( dev->description ) printf ( " (%s)\n", dev->description );
		else printf ( "(No description)\n" );
	}

	if ( !i )
	{
		ERRPRINT ( "No devices found.\n" );
		return EXIT_FAILURE;
	}

SELECT_DEV:
	printf ( "Enter the interface number: " );
	fscanf ( stdin, "%d", &n );

	if ( n < 0 || n > i )
	{
		ERRPRINT ( "Out of range.\n" );
		goto SELECT_DEV;
	}

	for ( dev = devs, i = 0; i < n; dev = dev->next, i++ );

	if ( ( handle = pcap_open_live ( dev->name, SG_BUFSZ, 1, SG_TIMEOUT, errbuf ) ) == NULL )
	{
		ERRPRINT ( "Could't open device %s: %s\n", dev->name, errbuf );
		pcap_freealldevs ( devs );
		return EXIT_FAILURE;
	}

	printf ( "Opened and sniffing %s\n", dev->name );

	dev = NULL;
	pcap_freealldevs ( devs );
	devs = NULL;

	atexit ( sg_cleanup );
	signal ( SIGINT, sg_sigh );
	signal ( SIGTERM, sg_sigh );

	if ( pcap_compile ( handle, &bpfp, SG_FILTER_EXP, 0, 0 ) )
	{
		ERRPRINT ( "Couldn't parse filter: %s\n", pcap_geterr ( handle ) );
		return EXIT_FAILURE;
	}

	SGF_SET ( SGF_FILTER );

	if ( pcap_setfilter ( handle, &bpfp ) )
	{
		ERRPRINT ( "Couldn't install filter: %s\n", pcap_geterr ( handle ) );
		return EXIT_FAILURE;
	}

	/* This is where the fun starts */

	SGF_SET ( SGF_LCTL );

	id = malloc ( SG_ID_SIZE + 1 );	/* Would be able to handle any? id */

SNIFF_LOOP:
	if ( ( n = pcap_next_ex ( handle, &pcap_hdr, &pkt_data ) ) > 0 && SGF_ISSET ( SGF_LCTL ) )
		goto PROC_PKT; /* proc_pkt(pkt_data, pcap_hdr->caplen); */

	else if ( !n ) goto SNIFF_LOOP;

	/* loop end */
	if ( n == -1 )
	{
		ERRPRINT ( "Error reading packet: %s\n", pcap_geterr ( handle ) );
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
	/* where the standard stuff gets done */
PROC_PKT:
	offset = ETHLEN;
	x = (pkt_data + offset);
	if ( ( i = ( ( struct ip4h* ) x )->ihl * 4 ) < 20 )
	{
		ERRPRINT ( "Invalid IP header length: %d\n", i );
		goto SNIFF_LOOP;
	}
	offset += i;
	x = (pkt_data + offset);

	if ( ( i = ( ( ( struct tcph* ) x )->doff ) * 4 ) < 20 )
	{
		ERRPRINT ( "Invalid TCP header length: %d\n", i );
		goto SNIFF_LOOP;
	}

	offset += i;
	if ( ( n = pcap_hdr->caplen - offset ) <= 0 ) goto SNIFF_LOOP;
	/* where the rtmp stuff gets done */
PROC_RTMP:
	x = ( pkt_data + offset );
	if ( ( ( struct hdr_fmt* ) x )->fmt == 1 )
	{
		offset++;
		x = ( pkt_data + offset );
		if ( ( ( struct msgt1* ) x )->tid == 0x13 )
		{
			goto PROC_AMF;
		}
	}
	goto SNIFF_LOOP;
	/* where the amf stuff gets done */
PROC_AMF:
	offset += sizeof ( struct msgt1 );
	n = ( pkt_data[offset++] << 8 ) | ( pkt_data[offset++] );
	offset += n + 17;
	n = ( pkt_data[offset++] << 8 ) | ( pkt_data[offset++] );

	if ( n > SG_ID_SIZE ) goto SNIFF_LOOP;	/* don't want no segfaults */

	for ( i = 0; i < n; i++ )
	{
		id[i] = pkt_data[offset+i];
	}
	id[i] = 0;
	if ( id[0] == 'd' ) goto PROC_MSG;
	else goto SNIFF_LOOP;
	/* where the message gets shit done to it */
PROC_MSG:
	offset += ++n;
	n = ( pkt_data[offset++] << 8 ) | pkt_data[offset++];
	if ( n == 0 ) goto SNIFF_LOOP;

	printf ( "%s: ", ( id+1 ) );
	for ( i = 0; i < n; i++ )
	{
		printf ( "%c", pkt_data[offset+i] );
	}
	printf ( "\n" );

	goto SNIFF_LOOP;
}

static void sg_sigh()
{
	if ( !SGF_ISSET ( SGF_LCTL ) ) exit ( EXIT_SUCCESS );
	SGF_OFF ( SGF_LCTL );
}

static void sg_cleanup ( void )
{
	if ( SGF_ISSET ( SGF_FILTER ) )
	{
		pcap_freecode ( &bpfp );
	}
	if ( handle != NULL )
	{
		pcap_close ( handle );
		handle = NULL;
	}

	if ( id != NULL )
	{
		free ( id );
		id = NULL;
	}
}
