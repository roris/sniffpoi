#pragma once

#include <stdint.h>

struct sp_sniff_private;

/**
 *
 * @caplen:     Length of the captured packet.
 * @packet:     The packet that was captured.
 * @private:	Made opaque so that pcap header will not have to be included
 * 		with the file.
 */

struct sp_sniff {
	struct sp_sniff_private *privates;

	const unsigned char *packet;

	uint32_t caplen;
};
