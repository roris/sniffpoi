#define _BSD_SOURCE 1

#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <pcap.h>

#if defined(WIN32) || defined(WIN64)
#define NEWLINE                 "\n\r"
#else
#define NEWLINE                 "\n"
#endif

#define MAX_IDL                 10
#define ETHLEN                  14

#define SG_BUFSZ                65535
#define SG_TIMEOUT              60

#define ERRPRINT(...)   fprintf(stderr, __VA_ARGS__)

typedef unsigned int uint;

struct ip4h {
        uint ihl:4;
        uint ver:4;
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

struct tcph {
        uint16_t src;
        uint16_t dest;
        uint32_t seq;
        uint32_t ack_seq;
        uint nsres:4;
        uint doff:4;
        uint fin:1;
        uint syn:1;
        uint rst:1;
        uint pauec:5;
};

struct rtmph {
        uint _0:6;
        uint fmt:2;
};

struct msg1 {
        uint8_t ts_delta[3];
        uint8_t len[3];
        uint8_t tid;
};

struct usr {
        char *id;
        char *name;
        struct usr *last;
        struct usr *next;
        struct usr *prev;
};

struct srv {
        struct srv *next;
        struct srv *prev;
        struct srv *last;       
        struct usr *usrs;

        FILE *logf;

        int port;               // local port used as an ID
        int strml[10];          // RTMP stream lengths
};

static struct srv *srvs;
static int srvc;
static char *id;
static struct bpf_program bpfp;
static pcap_t *handle;
static uint8_t sgf;

#define SGF_ON(b)       (sgf |= b)
#define SGF_OFF(b)      (sgf &= ~b)
#define SGF_ISON(b)     (sgf & b)
#define SGF_LCTL        0x1
#define SGF_FILTER      0x2
#define SG_FILTER_EXP  "src 111.102.245.226"

static char* gen_log_fname(int);
static struct srv* fprt(int);
static struct srv* cksrv(int);
static void sg_sigh(int);
static void sg_cleanup(void);
void free_all_srvs(void);
static struct usr* fusr(char *, struct srv*);
static struct usr* ckusr(char*, char*, struct srv*);
void free_all_usrs(struct srv*);
static void logtime(FILE *);
static void logpremsg(struct srv*, struct usr*);

int main(void)
{
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *devs, *dev;
        struct pcap_pkthdr *pcap_hdr;
        u_char *dat;
        void *x;
        struct srv *y;
        struct usr *z;

        int i, k, doff;

        if(pcap_findalldevs(&devs, errbuf)) {

                ERRPRINT("failed to retrieve the device list: %s" NEWLINE,
                        errbuf);
                return EXIT_FAILURE;
        }

        for(dev = devs, i = 0; dev; dev = dev->next) {

                printf("%d.%s", i++, dev->name);

                if(dev->description) printf(" (%s)\n", dev->description);
                else printf("(No desc)\n");
        }

        if(!i) {

                ERRPRINT("no devices found!\n");
                return EXIT_FAILURE;
        }

SEL_DEV:
        printf("enter the interface number: ");
        fscanf(stdin, "%d", &k);

        if(k < 0 || k > i) {

                ERRPRINT("out of range.\n");
                goto SEL_DEV;
        }

        for(dev = devs, i = 0; i < k; dev = dev->next, i++);

        if((handle = pcap_open_live(dev->name, SG_BUFSZ, 1, SG_TIMEOUT,
                                    errbuf)) == NULL) {

                ERRPRINT("couldn't open device %s: %s\n", dev->name, errbuf);
                pcap_freealldevs(devs);
                return EXIT_FAILURE;
        }

        printf("opened and sniffing on %s\n", dev->name);

        dev = NULL;
        pcap_freealldevs(devs);
        devs = NULL;

        atexit(sg_cleanup);
        signal(SIGINT, sg_sigh);        
        signal(SIGTERM, sg_sigh);

        if(pcap_compile(handle, &bpfp, SG_FILTER_EXP, 0, 0)) {

                ERRPRINT("couldn't compile the filter: %s\n",
                         pcap_geterr(handle));
                return EXIT_FAILURE;
        }

        SGF_ON(SGF_FILTER); // to free the filter later

        if(pcap_setfilter(handle, &bpfp)) {

                ERRPRINT("couldn't install filter: %s\n", pcap_geterr(handle));
                return EXIT_FAILURE;
        }

        SGF_ON(SGF_LCTL);

        id = malloc(MAX_IDL + 1);

SNIFF_LOOP:

        if(!SGF_ISON(SGF_LCTL)) goto LOOP_END;
        
        else if((k = pcap_next_ex(handle, &pcap_hdr, &dat)) > 0)
                goto PROC_PKT;

        else if(!k) goto SNIFF_LOOP;

        else if(k == -1) {

                ERRPRINT("error reading packet: %s\n", pcap_geterr(handle));
                return EXIT_FAILURE;
        }

LOOP_END:
        return EXIT_SUCCESS;

PROC_PKT:

        doff = ETHLEN;
        if((signed long)(pcap_hdr->caplen - doff) <= 0) goto SNIFF_LOOP;

        x = (dat + doff);

        if((i = ((struct ip4h*)x)->ihl * 4) < 20) {

                ERRPRINT("invalid ip header length: %d\n", i);
                goto SNIFF_LOOP;
        }

        doff += i;
        if((signed long)(pcap_hdr->caplen - doff) <= 0) goto SNIFF_LOOP;

        x = (dat + doff);        
        if((i = (((struct tcph*)x)->doff ) * 4) < 20) {

                ERRPRINT("invalid tcp header length: %d\n", i);
                goto SNIFF_LOOP;
        }
        
        doff += i;
        if((signed long)(pcap_hdr->caplen - doff) <= 0) goto SNIFF_LOOP;

        y = cksrv(((struct tcph*)x)->dest);
        /* TODO: connection cheking... FIN, RST, SYN etc... */
        
        /* RTMP stuff */
        x = (dat + doff);
        
        if(((struct rtmph*)x)->fmt == 1) {

                doff++;
                if((signed long)(pcap_hdr->caplen - doff) <= 0)
                        goto SNIFF_LOOP;
                
                x = (dat + doff);
                
                if(((struct msg1*)x)->tid == 0x13) goto PROC_AMF;
        }
        /* TODO: other message types */
        goto SNIFF_LOOP;

PROC_AMF:
        x = (dat + doff);

        /* TODO: get things like userlists and disconnects */
        doff += sizeof(struct msg1);
        if((signed long)(pcap_hdr->caplen - doff) <= 0) goto SNIFF_LOOP;

        k = (dat[doff] << 8) | dat[doff + 1];

        doff += k + 19;
        if((signed long)(pcap_hdr->caplen - doff) <= 0) goto SNIFF_LOOP;

        k = (dat[doff] << 8) | dat[doff + 1];

        doff += 2;
        if((signed long)(pcap_hdr->caplen - doff) <= 0) goto SNIFF_LOOP;        
        
        if(k > MAX_IDL) {
                ERRPRINT("MAX_IDL needs to be increased!\n");
                goto SNIFF_LOOP;
        }

        for(i = 0; i < k; i++) {
                id[i] = dat[doff+i];
        }
        id[i] = 0;

        if(id[0] != 'd') goto SNIFF_LOOP;

        z = ckusr(id+1, NULL, y);

        doff += ++k;
        if((signed long)(pcap_hdr->caplen - doff) <= 0) goto SNIFF_LOOP;

        k = (dat[doff] << 8) | dat[doff + 1];

        doff += 2;
        if((signed long)(pcap_hdr->caplen - doff) <= 0) goto SNIFF_LOOP;

        if(k == 0) goto SNIFF_LOOP;

        logpremsg(y, z);

        for(i = 0; i < k; i++) fprintf(y->logf, "%c", dat[doff + i]);

        fprintf(y->logf, NEWLINE);
        fflush(y->logf);

        printf("reached end!\n");
        goto SNIFF_LOOP;
}


static struct srv *fprt(int port)
{
        struct srv *x;

        for(x = srvs; x != NULL; x = srvs->next)
                if(x->port == port) return x;

        return NULL;
}

static struct usr *fusr(char *id, struct srv *s)
{
        struct usr *x;

        for(x = s->usrs; x != NULL; x = x->next)
                if(strncmp(x->id, id, MAX_IDL) == 0) return x;

        return NULL;
}

static struct srv *cksrv(int port)
{
        struct srv *n;
        char *c;

        if((n = fprt(port)) == NULL) {

                if((n = malloc(sizeof(struct srv))) == NULL) return NULL;

                n->port = port;
                c = gen_log_fname(port);

                if((n->logf = fopen(c , "w")) == NULL) {

                                free(c);
                                free(n);
                                return NULL;
                }

                free(c);
                n->usrs = NULL;

                if(srvs == NULL) {

                        srvs = n;
                        srvs->last = NULL;
                        srvs->prev = NULL;
                        srvs->next = NULL;

                } else if(srvs->last != NULL) {

                        n->prev = srvs->last;
                        n->prev->next = n;
                        srvs->last = n;
                        n->next = NULL;

                } else {

                        n->prev = srvs;
                        srvs->last = n;
                        srvs->next = n;
                }

                srvc++;
        }

        return n;
}

static struct usr *ckusr(char *id, char *n, struct srv* s)
{
        struct usr *u;

        if((u = fusr(id, s)) == NULL) {

                u = malloc(sizeof(struct usr));

                u->id = malloc(strlen(id) + 1);
                strcpy(u->id, id);

                if(n != NULL) { 

                        u->name = malloc(strlen(n) + 1);
                        strcpy(u->name, n);

                } else u->name = NULL;

                if(s->usrs == NULL) {

                        u->next = NULL;
                        u->prev = NULL;
                        u->last = NULL;
                        s->usrs = u;

                } else if(s->usrs->last == NULL) {

                        u->prev = s->usrs;
                        s->usrs->last = u;
                        s->usrs->next = u;

                } else {

                        u->prev = s->usrs->last;
                        u->prev->next = u;
                        u->next = NULL;
                        s->usrs->last = u;
                }
        }

        return u;
}

void free_all_usrs(struct srv *s)
{
        struct usr *u = s->usrs;
        struct usr *x;

        for(;u != NULL;) {

                x = u;
                u = u->next;

                if(x->name != NULL) free(x->name);

                free(x->id);
                free(x);
        }
}

void free_all_srvs(void)
{
        struct srv *x;

        for(; srvs != NULL; ) {

                x = srvs;
                srvs = srvs->next;
                free_all_usrs(x);
                free(x);
        }

        srvs = NULL;
        srvc = 0;
}

static char *gen_log_fname(int port)
{
        struct tm *ctm;
        time_t ct;
        char *s, *t;
        int nl;
        
        nl = log10(port) + 3;
        s = malloc(24 + nl);

        time(&ct);
        ctm = localtime(&ct);
        strftime(s, 20, "%F %H%M", ctm);
        
        t = malloc(nl + 1);
        snprintf(t, nl + 1, "[%d]", port);

        strcat(s, t);
        free(t);
        strcat(s, ".log");
        s[nl+23] = 0;

        return s;
}

static void logtime(FILE *fp)
{
        struct tm *ctm;
        time_t ct;
        char ts[11];

        time(&ct);
        ctm = localtime(&ct);

        strftime(ts, 11, "[%H:%M:%S]", ctm);
        fprintf(fp, "%s\t", ts);
}

void logpremsg(struct srv *s, struct usr *u)
{
        logtime(s->logf);

        if(u->name != NULL) 
                fprintf(s->logf, "<%s:%s> ", u->id, u->name);

        else fprintf(s->logf, "<%s> ", u->id);
}

static void sg_sigh(int sig)
{

        if(SGF_ISON(SGF_LCTL)) SGF_OFF(SGF_LCTL);

        else exit(EXIT_SUCCESS);
}

static void sg_cleanup(void)
{
        if(SGF_ISON(SGF_FILTER)) pcap_freecode(&bpfp);
        if(handle != NULL) pcap_close(handle);
        if( id != NULL) free(id);
        free_all_srvs();
}

