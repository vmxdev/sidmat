#include "sidmat_common.h"

#include <libnetfilter_log/libnetfilter_log.h>

/*
 * print help text
 */
static void
print_app_usage(char *prog)
{
	printf("Usage: %s nflog_group regex\n", prog);
	printf("\n");
	printf("Options:\n");
	printf("    nflog_group    nflog group number.\n");
	printf("          regex    Regular expression for which you want to select DNS responses.\n");
	printf("\n");
}

static int
got_packet(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
	struct nflog_data *nfa, void *args)
{
	char *packet;
	struct user_data *data = (struct user_data *)args;
	int payload_len = nflog_get_payload(nfa, &packet);

	if (payload_len < 0) {
		return 0;
	}

	dns_ip_packet(packet, data);
	return 0;
}

int
main(int argc, char *argv[])
{
	struct nflog_handle *h;
	struct nflog_g_handle *qh;
	int rv, fd;
	char buf[4096];
	char *regstr;
	int group;

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
		opt = argv[3];
	}

	if (!sidmat_init(&data, argv[2], opt)) {
		return EXIT_FAILURE;
	}

	group = atoi(argv[1]);

	h = nflog_open();
	if (!h) {
		fprintf(stderr, "nflog_open() error\n");
		return EXIT_FAILURE;
	}

	if (nflog_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "nflog_unbind_pf() error\n");
		return EXIT_FAILURE;
	}

	if (nflog_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "nflog_bind_pf() error\n");
		return EXIT_FAILURE;
	}

	qh = nflog_bind_group(h, group);
	if (!qh) {
		fprintf(stderr, "no handle for group %d\n", group);
		return EXIT_FAILURE;
	}

	if (nflog_set_mode(qh, NFULNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet copy mode\n");
		return EXIT_FAILURE;
	}

	fd = nflog_fd(h);

	nflog_callback_register(qh, &got_packet, &data);

	/* set output buffering mode */
	setvbuf(stdout, NULL, _IOLBF, 1024);

	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		/* handle messages in just-received packet */
		nflog_handle_packet(h, buf, rv);
	}

	nflog_unbind_group(qh);
	nflog_close(h);

	regfree(&data.re);

	return EXIT_SUCCESS;
}

