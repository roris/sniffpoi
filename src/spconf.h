#pragma once

#include <sys/types.h>

/*
 * @devname:      Name of the device to sniff on, passed to pcap_open_live.
 * @snaplen:      Snaplen passed to pcap_open_live.
 * @max_clients:  Maximum number of allowed clients.
 * @filter:       Filter-expression passed to pcap_compile.
 * @optimize:     Optimization flag passed to pcap_compile.
 */

struct sp_config {
	char    *devname;
	char    *filter;
	int      snaplen;
	int      timeout;
	int      max_clients;
	int      optimize;
};

