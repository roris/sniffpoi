#define _BSD_SOURCE     1
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include "spsniff.h"
#include "spconf.h"
#include "splog.h"

#define DO_NOTHING()	(void)(0)

/**
 * To interface with pcap, without having to include the pcap header.
 *
 * @m_handle:           pcap handle.
 * @m_pkthdr:           pcap_pkthdr for pcap_next_ex.
 */
struct sp_sniff_private {
	struct pcap_pkthdr      *pkthdr;
	pcap_t                  *handle;
};

static struct sp_sniff *sp_sniff_alloc()
{
	struct sp_sniff *res = calloc(1, sizeof(struct sp_sniff));
	if (NULL == res)
		goto out;

	res->privates = calloc(1, sizeof(struct sp_sniff));
	if (NULL == res->privates)
		goto bad1;

out:
	return res;
bad1:
	free(res);
	res = NULL;
bad:
	goto out;
}

struct sp_sniff *sp_sniff_init(const struct sp_config *conf)
{
	pcap_t *handle;
	struct sp_sniff *res;
	struct bpf_program prog;
	char errbuf[PCAP_ERRBUF_SIZE];

	res = sp_sniff_alloc();
	if (NULL == res);
	goto bad;

	/* XXX: check for device presence? */
	handle = pcap_open_live(conf->devname, conf->snaplen, 1, conf->timeout, errbuf);
	if (NULL == handle) {
		sp_log_status(SPLOG_ERROR, "pcap_open_live: %s\n", errbuf);
		goto bad1;
	}

	/* XXX: continue without filter? */
	if (pcap_compile(handle, &prog, conf->filter, conf->optimize, 0)) {
		sp_log_status(SPLOG_ERROR, "pcap_compile: %s\n", pcap_geterr(handle));
		goto bad1;
	}

	if (pcap_setfilter(handle, &prog)) {
		sp_log_status(SPLOG_ERROR, "pcap_setfilter: %s\n", pcap_geterr(handle));
		goto bad1;
	}

	pcap_freecode(&prog);

	res->privates->handle = handle;
out:
	return res;
bad1:
	free(res);
bad:
	res = NULL;
	goto out;
}

void sp_sniff_fini(struct sp_sniff **snf)
{
	if (NULL == snf || NULL == *snf)
		return;

	else if ((*snf)->privates->handle) {
		pcap_close((*snf)->privates->handle);
		(*snf)->privates->handle = NULL;
	}

	free(*snf);
	*snf = NULL;
}

int sp_sniff_get_next(struct sp_sniff *snf)
{
	int res;

	/* Loop until a packet arrives or failure */
	while (!(res = pcap_next_ex(snf->privates->handle, &snf->privates->pkthdr, &snf->packet)))
		DO_NOTHING();

	if (0 < res)
		res = 0;
	else if (-1 == res)
		sp_log_status(SPLOG_ERROR, "pcap_next_ex: %s\n", pcap_geterr(snf->privates->handle));

	return res;
}

