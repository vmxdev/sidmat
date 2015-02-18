#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <regex.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
	u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
	#define IP_RF 0x8000            /* reserved fragment flag */
	#define IP_DF 0x4000            /* dont fragment flag */
	#define IP_MF 0x2000            /* more fragments flag */
	#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	u_char  ip_ttl;                 /* time to live */
	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* UDP header */
struct sniff_udp
{
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};

/*
 * global variables
 */
static regex_t re;
static u_int *addrs = NULL, naddrs = 0;

/*
 * print help text
 */
static void
print_app_usage(char *prog)
{
	printf("Usage: %s interface regex\n", prog);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("        regex    Regular expression for which you want to select DNS responses.\n");
	printf("\n");
}

/*
 * ipv4 comparator
 */
static int
ip4_cmp(const void *m1, const void *m2)
{
	u_int *ip1 = (u_int *) m1;
	u_int *ip2 = (u_int *) m2;
	return (*ip1 - *ip2);
}

/*
 * Read name in DNS format with compression
 */
static int
read_dns_name(u_char *base, u_char *ptr, char *name)
{
	u_char c;
	int len;
	int count = 0, compressed = 0;

	for (;;) {
		int i;

		c = *ptr;

		if ((c & 0xc0) == 0xc0) {
			int offset;

			offset = (ntohs(*(u_short *)(ptr)) - 0xc000);
			ptr = base + offset;
			count += 2;
			compressed = 1;
			continue;
		}

		len = c;
		if (len == 0) {
			if (count > 0) {
				*(name - 1) = '\0';
				if (!compressed) count++;
			} else {
				*name = '\0';
			}
			break;
		}

		ptr++;
		if (!compressed) count++;
		for (i=0; i<len; i++, name++, ptr++) {
			*name = *ptr;
			if (!compressed) count++;
		}
		*name++ = '.';
	}

	return count;
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	/* declare pointers to packet headers */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_udp *udp;            /* The UDP header */
	const HEADER *dnsh;                     /* The DNS header */
	u_char *resp, *rptr;                    /* payload */

	int size_ip;
	int name_off, n_ans;

	char name[256];

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		fprintf(stderr, "   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	if (ip->ip_p != IPPROTO_UDP) {
		/* Handle only UDP */
		return;
	}

	udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
	dnsh = (HEADER *)((char *)udp + sizeof(struct sniff_udp));

	if ((dnsh->qr != 1) || (dnsh->rcode != 0) || (dnsh->qdcount == 0) || (dnsh->ancount == 0)) {
		return;
	}

	resp = (u_char *)dnsh;
	rptr = (u_char *)((char *)dnsh + sizeof(HEADER));

	name_off = read_dns_name(resp, rptr, name);
	/* check DNS query against regex */
	if (regexec(&re, name, (size_t) 0, NULL, 0) != 0) {
		return;
	}
	rptr += name_off;

	rptr += sizeof(u_short) * 2;

	for (n_ans = 0; n_ans < ntohs(dnsh->ancount); n_ans++) {
		int atype, rdlength;

		name_off = read_dns_name(resp, rptr, name);
		rptr += name_off;

		atype = ntohs(*(u_short *)rptr);
		rptr += sizeof(u_short) * 4; /* skip class, ttl */

		rdlength = ntohs(*(u_short *)rptr);
		rptr += sizeof(u_short);

		if ((atype == 1) && (rdlength == 4)) {
			int addr_new = 0;

			if (addrs) {
				if (!bsearch(rptr, addrs, naddrs, sizeof(u_int), &ip4_cmp)) {
					naddrs++;
					addrs = realloc(addrs, naddrs * sizeof(u_int));
					memcpy(&addrs[naddrs - 1], rptr, sizeof(u_int));
					qsort(addrs, naddrs, sizeof(u_int), ip4_cmp);
					addr_new = 1;
				}
			} else {
				addrs = malloc(sizeof(u_int));
				naddrs = 1;
				memcpy(addrs, rptr, sizeof(u_int));
				addr_new = 1;
			}

			if (addr_new) {
				printf("%d.%d.%d.%d\n", *(rptr + 0), *(rptr + 1), *(rptr + 2), *(rptr + 3));
			}
		}
		rptr += rdlength;
	}
}

int
main(int argc, char *argv[])
{
	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "port 53";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	char *regstr;

	if (argc != 3) {
		print_app_usage(argv[0]);
		return EXIT_FAILURE;
	}

	/* compile regex */
	regstr = argv[2];
	if (regcomp(&re, regstr, REG_EXTENDED | REG_NOSUB) != 0) {
		fprintf(stderr, "Couldn't compile regex '%s'\n", regstr);
		return EXIT_FAILURE;
	}

	dev = argv[1];
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
			dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		return EXIT_FAILURE;
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
			filter_exp, pcap_geterr(handle));
		return EXIT_FAILURE;
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
			filter_exp, pcap_geterr(handle));
		return EXIT_FAILURE;
	}

	/* now we can set our callback function */
	pcap_loop(handle, 0, got_packet, NULL);

	/* FIXME: unreachable code */
	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	regfree(&re);

	return EXIT_SUCCESS;
}

