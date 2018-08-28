#ifndef sidmat_common_h_included
#define sidmat_common_h_included

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <regex.h>

/* host name maximum length */
#define HOSTNAME_MAX 256

/* max addresses in list (256M) */
#define SMAXADDRS (256 * 1024 * 1024)

#define NOMEM_EXIT()                                                    \
do {                                                                    \
	fprintf(stderr, "Insufficient memory, file %s, near line %d\n", \
		__FILE__, __LINE__);                                    \
	exit(1);                                                        \
} while(0)

/* IP header */
struct sniff_ip
{
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
 * user data
 */

struct user_data
{
	regex_t re;
	uint32_t *addrs;
	size_t    naddrs;

	int debug, info, not_unique;
};


/*
 * ipv4 comparator
 */
static int
ip4_cmp(const void *m1, const void *m2)
{
	const uint32_t *ip1 = m1;
	const uint32_t *ip2 = m2;
	if(*ip1 > *ip2) {
		return 1;
	} else {
		return(*ip1 < *ip2) ? -1 : 0;
	}
}

/*
 * Read name in DNS format with compression
 */
static int
read_dns_name(u_char *base, u_char *ptr, char *name, int psize)
{
	u_char c;
	int len;
	int count = 0, compressed = 0;
	char *base_name = name;

#define SAFE_PTRS_INC(PTR, COUNT, NAME)\
do {\
	ptr += PTR;\
	if ((ptr > (base + psize)) || (ptr < base)) return 0;\
	count += COUNT;\
	if ((count > HOSTNAME_MAX) || (count < 0)) return 0;\
	name += NAME;\
	if ((name > (base_name + HOSTNAME_MAX)) || (name < base_name)) return 0;\
} while (0)

	for (;;) {
		int i;

		c = *ptr;

		if ((c & 0xc0) == 0xc0) {
			int offset;

			offset = (ntohs(*(u_short *)(ptr)) - 0xc000);
			ptr = base;
			SAFE_PTRS_INC(offset, 2, 0); /* ptr += offset; count += 2; */
			compressed = 1;
			continue;
		}

		len = c;
		if (len == 0) {
			if (count > 0) {
				*(name - 1) = '\0';
				if (!compressed) SAFE_PTRS_INC(0, 1, 0); /*count++;*/
			} else {
				*name = '\0';
			}
			break;
		}

		ptr++;
		if (!compressed) count++;
		for (i=0; i<len; i++) {
			*name = *ptr;
			if (!compressed) SAFE_PTRS_INC(0, 1, 0); /*count++;*/
			SAFE_PTRS_INC(1, 0, 1); /* name++; ptr++; */
		}
		*name = '.';
		SAFE_PTRS_INC(0, 0, 1); /* name++; */
	}

	return count;

#undef SAFE_PTRS_INC
}

static void
dns_ip_packet(char *packet, struct user_data *data)
{
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_udp *udp;            /* The UDP header */
	const HEADER *dnsh;
	u_char *dnspacket, *rptr;

	int size_ip;
	int name_off, n_ans;
	int psize;

	char name[HOSTNAME_MAX], debug_name[HOSTNAME_MAX];
	int print_addr = 0;

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		fprintf(stderr, "   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	if (ip->ip_p != IPPROTO_UDP) {
		/* Handle only UDP */
		return;
	}

	udp = (struct sniff_udp*)(packet + size_ip);
	psize = ntohs(udp->uh_ulen) - sizeof(struct sniff_udp);
	dnsh = (HEADER *)((char *)udp + sizeof(struct sniff_udp));

	if ((dnsh->qr != 1) || (dnsh->rcode != 0) || (dnsh->qdcount == 0) || (dnsh->ancount == 0)) {
		return;
	}

	dnspacket = (u_char *)dnsh;
	rptr = dnspacket;

#define SAFE_PPTR_INC(PTR, N)\
do {\
	PTR += N;\
	if (PTR > (dnspacket + psize)) return;\
} while (0)

	SAFE_PPTR_INC(rptr, sizeof(HEADER));

	name_off = read_dns_name(dnspacket, rptr, name, psize);
	if (name_off == 0) return;

	/* check DNS query against regex */
	if (regexec(&(data->re), name, (size_t) 0, NULL, 0) != 0) {
		return;
	}
	/* store name for debug */
	if (data->debug || data->info) {
		strncpy(debug_name, name, HOSTNAME_MAX);
	}

	SAFE_PPTR_INC(rptr, name_off);
	SAFE_PPTR_INC(rptr, sizeof(u_short) * 2);

	for (n_ans = 0; n_ans < ntohs(dnsh->ancount); n_ans++) {
		int atype, rdlength;

		name_off = read_dns_name(dnspacket, rptr, name, psize);
		if (name_off == 0) return;
		SAFE_PPTR_INC(rptr, name_off);

		atype = ntohs(*(u_short *)rptr);
		SAFE_PPTR_INC(rptr, sizeof(u_short) * 4); /* skip class, ttl */

		rdlength = ntohs(*(u_short *)rptr);
		SAFE_PPTR_INC(rptr, sizeof(u_short));

		if ((atype == 1) && (rdlength == 4) && (!data->not_unique)) {

			if (data->addrs) {
				if (!bsearch(rptr, data->addrs, data->naddrs, sizeof(uint32_t), &ip4_cmp)) {
					data->naddrs++;
					if (data->naddrs > SMAXADDRS) {
						/* reset list */
						free(data->addrs);
						data->addrs = NULL;
						data->naddrs = 1;
					}
					data->addrs = realloc(data->addrs, data->naddrs * sizeof(uint32_t));
					memcpy(&data->addrs[data->naddrs - 1], rptr, sizeof(uint32_t));
					qsort(data->addrs, data->naddrs, sizeof(uint32_t), &ip4_cmp);
					print_addr = 1;
				}
			} else {
				data->addrs = malloc(sizeof(uint32_t));
				data->naddrs = 1;
				memcpy(data->addrs, rptr, sizeof(uint32_t));
				print_addr = 1;
			}
		}

		if ((atype == 1) && (rdlength == 4) && (data->not_unique)) {
			print_addr = 1;
		}

		if (print_addr) {
			if (data->debug) {
				fprintf(stderr, "# %s\n", debug_name);
			}
			printf("%d.%d.%d.%d", *(rptr + 0), *(rptr + 1), *(rptr + 2), *(rptr + 3));
			if (data->info) {
				printf("\t%s", debug_name);
			}
			printf("\n");
		}
		SAFE_PPTR_INC(rptr, rdlength);
	}
#undef SAFE_PPTR_INC
	return;
}

static char *
read_from_file(const char *fn)
{
	FILE *f;
	char *regstr;
	size_t size;

	f = fopen(fn, "r");
	if (!f) {
		return NULL;
	}
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	regstr = malloc(size);
	if (!regstr) {
		NOMEM_EXIT();
	}
	fseek(f, 0, SEEK_SET);
	fread(regstr, 1, size, f);
	fclose(f);

	return regstr;
}

static int
sidmat_init(struct user_data *data, const char *r, const char *opt)
{
	char *regstr = NULL;

	data->debug = data->not_unique = data->info = 0;

	if (opt) {
		if (strchr(opt, 'd') != NULL) {
			data->debug = 1;
		}
		if (strchr(opt, 'i') != NULL) {
			data->info = 1;
		}
		if (strchr(opt, 'u') != NULL) {
			data->not_unique = 1;
		}

		if (strchr(opt, 'f') != NULL) {
			regstr = read_from_file(r);
			if (!regstr) {
				fprintf(stderr, "Can't open %s\n", r);
				return 0;
			}
		}
	}

	if (!regstr) {
		regstr = strdup(r);
		if (!regstr) {
			NOMEM_EXIT();
		}
	}
	/* compile regex */
	if (regcomp(&(data->re), regstr, REG_EXTENDED | REG_NOSUB) != 0) {
		fprintf(stderr, "Couldn't compile regex '%s'\n", regstr);
		return 0;
	}
	free(regstr);

	return 1;
}

#endif

