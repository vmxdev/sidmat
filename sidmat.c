#include "sidmat_common.h"
#include <pcap.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

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

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	/* declare pointers to packet headers */
	const struct sniff_ip *ip;              /* The IP header */
	int size_ip;
	struct user_data *data;

	(void)header;

	data = (struct user_data *)args;

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

	dns_ip_packet((char *)packet + SIZE_ETHERNET, data);
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

	struct user_data data;

	data.addrs = NULL;
	data.naddrs = 0;
	data.debug = 0;

	if (argc < 3) {
		print_app_usage(argv[0]);
		return EXIT_FAILURE;
	}

	/* additional options */
	if (argc == 4) {
		if (strchr(argv[3], 'd') != NULL) {
			data.debug = 1;
		}
	}

	/* compile regex */
	regstr = argv[2];
	if (regcomp(&data.re, regstr, REG_EXTENDED | REG_NOSUB) != 0) {
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

	/* set output buffering mode */
	setvbuf(stdout, NULL, _IOLBF, 1024);

	/* now we can set our callback function */
	pcap_loop(handle, 0, got_packet, (u_char *)&data);

	/* FIXME: unreachable code */
	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	regfree(&data.re);

	return EXIT_SUCCESS;
}

