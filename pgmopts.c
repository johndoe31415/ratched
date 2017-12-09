/**
 *	ratched - TLS connection router that performs a man-in-the-middle attack
 *	Copyright (C) 2017-2017 Johannes Bauer
 *
 *	This file is part of ratched.
 *
 *	ratched is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; this program is ONLY licensed under
 *	version 3 of the License, later versions are explicitly excluded.
 *
 *	ratched is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with ratched; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *	Johannes Bauer <JohannesBauer@gmx.de>
**/

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "pgmopts.h"
#include "parse.h"
#include "tools.h"
#include "stringlist.h"
#include "keyvaluelist.h"
#include "ipfwd.h"
#include "intercept_config.h"

static struct pgmopts_t pgm_options_rw = {
	.log = {
		.level = LLVL_INFO,
	},
	.network = {
		.initial_read_timeout = 1.0,
		.server_socket = {
			.listen = 10,
		},
	},
	.forged_certs = {
		.recalculate_key_identifiers = true,
	},
	.keyspec = {
		.keytype = KEYTYPE_RSA,
		.rsa = {
			.modulus_length_bits = 2048,
		},
	},
};
const struct pgmopts_t *pgm_options = &pgm_options_rw;

#define PARSER_MAX_ERROR_LEN		128
static char parsing_error[PARSER_MAX_ERROR_LEN];

void show_syntax(const char *pgmbinary) {
	if (strlen(parsing_error)) {
		fprintf(stderr, "error: %s\n\n", parsing_error);
	}
	/* Begin of help page -- auto-generated, do not edit! */
	fprintf(stderr, "usage: ratched [-c path] [-f hostname:port] [--single-shot] [--dump-certs]\n");
	fprintf(stderr, "               [--keyspec keyspec] [--initial-read-timeout secs]\n");
	fprintf(stderr, "               [--mark-forged-certificates] [--no-recalculate-keyids]\n");
	fprintf(stderr, "               [--daemonize] [--logfile file] [--flush-logs] [--crl-uri uri]\n");
	fprintf(stderr, "               [--ocsp-uri uri] [--write-memdumps-into-files]\n");
	fprintf(stderr, "               [--use-ipv6-encapsulation] [-l hostname:port]\n");
	fprintf(stderr, "               [-d key=value[,key=value,...]] [-i hostname[,key=value,...]]\n");
	fprintf(stderr, "               [--pcap-comment comment] [-o filename] [-v]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "ratched - TLS connection router that performs a man-in-the-middle attack\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "optional arguments:\n");
	fprintf(stderr, "  -c path, --config-dir path\n");
	fprintf(stderr, "                        Configuration directory where the default root CA\n");
	fprintf(stderr, "                        certificate, CA keypair and server keypair are stored.\n");
	fprintf(stderr, "                        Defaults to ~/.config/ratched\n");
	fprintf(stderr, "  -f hostname:port, --local-fwd hostname:port\n");
	fprintf(stderr, "                        When local connection to listening port is made, the\n");
	fprintf(stderr, "                        connection is discarded by default. Specifying this\n");
	fprintf(stderr, "                        option makes ratched forward to the given\n");
	fprintf(stderr, "                        hostname/port combination instead. Useful for testing\n");
	fprintf(stderr, "                        the proxy without the iptables REDIRECT.\n");
	fprintf(stderr, "  --single-shot         Only handle a single connection and terminate directly\n");
	fprintf(stderr, "                        after. Useful for debugging purposes.\n");
	fprintf(stderr, "  --dump-certs          Print created certificates for each intercepted\n");
	fprintf(stderr, "                        connection in the log file. Note that in many cases\n");
	fprintf(stderr, "                        you will also need to increase the log level to at\n");
	fprintf(stderr, "                        least DEBUG in order to see certificates.\n");
	fprintf(stderr, "  --keyspec keyspec     Specification for the private keys that should be\n");
	fprintf(stderr, "                        used. Can be either in the form \"rsa:bitlen\" or\n");
	fprintf(stderr, "                        \"ecc:curvename\". Valid choices, therefore, would be,\n");
	fprintf(stderr, "                        for example, \"rsa:1024\" or \"ecc:secp256r1\". Defaults\n");
	fprintf(stderr, "                        to rsa:2048\n");
	fprintf(stderr, "  --initial-read-timeout secs\n");
	fprintf(stderr, "                        Specifies the amount of time in seconds (as a floating\n");
	fprintf(stderr, "                        point number) that ratched waits for the client to\n");
	fprintf(stderr, "                        provide its ClientHello before giving up. The default\n");
	fprintf(stderr, "                        is 1.0 secs.\n");
	fprintf(stderr, "  --mark-forged-certificates\n");
	fprintf(stderr, "                        Include an OU=ratched entry to the subjects of all\n");
	fprintf(stderr, "                        created certificates (including dynamically forged\n");
	fprintf(stderr, "                        client certificates) for easy debugging.\n");
	fprintf(stderr, "  --no-recalculate-keyids\n");
	fprintf(stderr, "                        When forging client certificates, by default the\n");
	fprintf(stderr, "                        subject and authority key identifiers are removed and\n");
	fprintf(stderr, "                        recreated to fit the actually used key ids. With this\n");
	fprintf(stderr, "                        option, they're used as-is (i.e., the key identifier\n");
	fprintf(stderr, "                        metadata will not fit the actually used keys). This\n");
	fprintf(stderr, "                        option might expose bugs in certain frameworks which\n");
	fprintf(stderr, "                        regard these identifiers as trusted information.\n");
	fprintf(stderr, "  --daemonize           Do not run in foreground mode, but in the background\n");
	fprintf(stderr, "                        as a daemon.\n");
	fprintf(stderr, "  --logfile file        Instead of logging to stderr, redirect logs to given\n");
	fprintf(stderr, "                        file.\n");
	fprintf(stderr, "  --flush-logs          Flush logfile after each call to logmsg(). Decreases\n");
	fprintf(stderr, "                        performance, but gives line-buffered logs.\n");
	fprintf(stderr, "  --crl-uri uri         Encode the given URI into the CRL Distribution Point\n");
	fprintf(stderr, "                        X.509 extension of server certificates.\n");
	fprintf(stderr, "  --ocsp-uri uri        Encode the given URI into the Authority Info Access\n");
	fprintf(stderr, "                        X.509 extension of server certificates as the OCSP\n");
	fprintf(stderr, "                        responder URI.\n");
	fprintf(stderr, "  --write-memdumps-into-files\n");
	fprintf(stderr, "                        When dumping a piece of memory in the log, also output\n");
	fprintf(stderr, "                        its binary equivalent into a file called\n");
	fprintf(stderr, "                        hexdump_####.bin, where #### is an ascending number.\n");
	fprintf(stderr, "                        Useful for debugging of internal data structures.\n");
	fprintf(stderr, "  --use-ipv6-encapsulation\n");
	fprintf(stderr, "                        For writing the PCAPNG file format, usually IPv4 is\n");
	fprintf(stderr, "                        emulated. This has the drawback that when one IPv4\n");
	fprintf(stderr, "                        endpoint serves multiple servers via the TLS Server\n");
	fprintf(stderr, "                        Name Indication extension, they cannot be\n");
	fprintf(stderr, "                        differentiated by their hostname. With this parameter,\n");
	fprintf(stderr, "                        ratched wraps the packets in IPv4-in-IPv6 emulation\n");
	fprintf(stderr, "                        and assigns different IPv6 addresses for different\n");
	fprintf(stderr, "                        server names, thus enabling accurate name resolution.\n");
	fprintf(stderr, "  -l hostname:port, --listen hostname:port\n");
	fprintf(stderr, "                        Specify the address and port that ratched is listening\n");
	fprintf(stderr, "                        on. Defaults to 127.0.0.1:9999.\n");
	fprintf(stderr, "  -d key=value[,key=value,...], --defaults key=value[,key=value,...]\n");
	fprintf(stderr, "                        Specify the server and client connection parameters\n");
	fprintf(stderr, "                        for all hosts that are not explicitly listed via a\n");
	fprintf(stderr, "                        --intercept option. Arguments are given in a key=value\n");
	fprintf(stderr, "                        fashion; valid arguments are shown below.\n");
	fprintf(stderr, "  -i hostname[,key=value,...], --intercept hostname[,key=value,...]\n");
	fprintf(stderr, "                        Intercept only a specific host name, as indicated by\n");
	fprintf(stderr, "                        the Server Name Indication inside the ClientHello. Can\n");
	fprintf(stderr, "                        be specified multiple times to include interception or\n");
	fprintf(stderr, "                        more than one host. Additional arguments can be\n");
	fprintf(stderr, "                        specified in a key=value fashion to further define\n");
	fprintf(stderr, "                        interception parameters for that particular host.\n");
	fprintf(stderr, "  --pcap-comment comment\n");
	fprintf(stderr, "                        Store a particular piece of information inside the\n");
	fprintf(stderr, "                        PCAPNG header as a comment.\n");
	fprintf(stderr, "  -o filename, --outfile filename\n");
	fprintf(stderr, "                        Specifies the PCAPNG file that the intercepted traffic\n");
	fprintf(stderr, "                        is written to. Mandatory argument.\n");
	fprintf(stderr, "  -v, --verbose         Increase logging verbosity.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "The arguments which are valid for the --intercept argument are as follows:\n");
	fprintf(stderr, "  intercept=[opportunistic|mandatory|forward|reject]\n");
	fprintf(stderr, "                        Specifies the mode that ratched should act in for\n");
	fprintf(stderr, "                        this particular connection. Opportunistic TLS\n");
	fprintf(stderr, "                        interception is the default; it means that TLS\n");
	fprintf(stderr, "                        interception is tried first. Should it fail, however\n");
	fprintf(stderr, "                        (because someone tries to send non-TLS traffic), it\n");
	fprintf(stderr, "                        falls back to 'forward' mode (i.e., forwarding all\n");
	fprintf(stderr, "                        data unmodified). Mandatory TLS interception means\n");
	fprintf(stderr, "                        that if no TLS interception is possible, the\n");
	fprintf(stderr, "                        connection is terminated. 'forward', as explained,\n");
	fprintf(stderr, "                        simply forwards everything unmodified. 'reject'\n");
	fprintf(stderr, "                        closes the connection altogether, regardless of the\n");
	fprintf(stderr, "                        type of seen traffic.\n");
	fprintf(stderr, "  s_tlsversions=versions\n");
	fprintf(stderr, "                        Colon-separated string that specifies the acceptable\n");
	fprintf(stderr, "                        TLS version for the ratched server component. Valid\n");
	fprintf(stderr, "                        elements are ssl2, ssl3, tls10, tls11, tls12, tls13.\n");
	fprintf(stderr, "                        Defaults to tls10:tls11:tls12.\n");
	fprintf(stderr, "  s_reqclientcert=bool  Ask all connecting clients to the server side of the\n");
	fprintf(stderr, "                        TLS proxy for a client certificate. If not\n");
	fprintf(stderr, "                        replacement certificate (at least certfile and\n");
	fprintf(stderr, "                        keyfile) is given, forge all metadata of the incoming\n");
	fprintf(stderr, "                        certificate. If a certfile/keyfile is given, this\n");
	fprintf(stderr, "                        option is implied.\n");
	fprintf(stderr, "  s_certfile=filename   Specifies an X.509 certificate in PEM format that\n");
	fprintf(stderr, "                        should be used by ratched as the server certificate.\n");
	fprintf(stderr, "                        By default, this certificate is automatically\n");
	fprintf(stderr, "                        generated. Must be used in conjunction with\n");
	fprintf(stderr, "                        s_keyfile.\n");
	fprintf(stderr, "  s_keyfile=filename    Specifies the private key for the given server\n");
	fprintf(stderr, "                        certificate, in PEM format.\n");
	fprintf(stderr, "  s_chainfile=filename  Specifies the X.509 certificate chain that is to be\n");
	fprintf(stderr, "                        sent to the client, in PEM format.\n");
	fprintf(stderr, "  s_cacert=filename     The X.509 CA certificate that issues server\n");
	fprintf(stderr, "                        certificates, in PEM format.\n");
	fprintf(stderr, "  s_cakey=filename      The X.509 CA certificate key that signs server\n");
	fprintf(stderr, "                        certificates, in PEM format.\n");
	fprintf(stderr, "  s_ciphers=ciphers     The cipher suite string that the ratched TLS server\n");
	fprintf(stderr, "                        uses.\n");
	fprintf(stderr, "  s_groups=groups       The key agreement 'supported groups' string (formerly\n");
	fprintf(stderr, "                        known as 'elliptic curves') that the ratched TLS\n");
	fprintf(stderr, "                        server uses.\n");
	fprintf(stderr, "  s_sigalgs=algs        The key agreement 'signature algorithms' string which\n");
	fprintf(stderr, "                        the ratched TLS server uses.\n");
	fprintf(stderr, "  c_tlsversions=versions\n");
	fprintf(stderr, "                        Colon-separated string that specifies the acceptable\n");
	fprintf(stderr, "                        TLS version for the ratched client component. Valid\n");
	fprintf(stderr, "                        elements are ssl2, ssl3, tls10, tls11, tls12, tls13.\n");
	fprintf(stderr, "                        Defaults to tls10:tls11:tls12.\n");
	fprintf(stderr, "  c_certfile=filename   Specifies an X.509 certificate in PEM format that\n");
	fprintf(stderr, "                        should be used by ratched as a client certificate. It\n");
	fprintf(stderr, "                        will only be used when the connecting client also\n");
	fprintf(stderr, "                        provided a client certificate. Must be used in\n");
	fprintf(stderr, "                        conjunction with c_keyfile.\n");
	fprintf(stderr, "  c_keyfile=filename    The private key for the given client certificate, in\n");
	fprintf(stderr, "                        PEM format.\n");
	fprintf(stderr, "  c_chainfile=filename  The X.509 certificate chain that is to be sent to the\n");
	fprintf(stderr, "                        server, in PEM format.\n");
	fprintf(stderr, "  c_ciphers=ciphers     The cipher suite string that the ratched TLS client\n");
	fprintf(stderr, "                        uses.\n");
	fprintf(stderr, "  c_groups=groups       The key agreement 'supported groups' string (formerly\n");
	fprintf(stderr, "                        known as 'elliptic curves') that the ratched TLS\n");
	fprintf(stderr, "                        client uses.\n");
	fprintf(stderr, "  c_sigalgs=algs        The key agreement 'signature algorithms' string which\n");
	fprintf(stderr, "                        the ratched TLS client uses.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "examples:\n");
	fprintf(stderr, "    $ ratched -o output.pcapng\n");
	fprintf(stderr, "      Open up local port 9999 and listen for incoming connections, intercept\n");
	fprintf(stderr, "      all TLS traffic and write output into given capture file.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "    $ ratched -f google.com:443 -o output.pcapng\n");
	fprintf(stderr, "      Same as before, but redirect all traffic of which the destination cannot\n");
	fprintf(stderr, "      be determined (e.g., local connections to port 9999) to google.com on\n");
	fprintf(stderr, "      port 443.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "    $ ratched -vvv --dump-certs -o output.pcapng\n");
	fprintf(stderr, "      Be much more verbose during interception and also print out forged\n");
	fprintf(stderr, "      certificates in the log.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "    $ ratched --defaults intercept=forward -intercept --intercept www.johannes-bauer.com -o output.pcapng\n");
	fprintf(stderr, "      Do not generally intercept connections (but rather forward all traffic\n");
	fprintf(stderr, "      unmodified) except for connections with Server Name Indication\n");
	fprintf(stderr, "      www.johannes-bauer.com, on which interception is performed.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "    $ ratched --intercept www.johannes-bauer.com,s_reqclientcert=true -o output.pcapng\n");
	fprintf(stderr, "      Generally do not request client certificates from connecting peers\n");
	fprintf(stderr, "      except for connections with Server Name Indication www.johannes-\n");
	fprintf(stderr, "      bauer.com, where clients are sent a CertificateRequest TLS message. If\n");
	fprintf(stderr, "      clients do not provide a client certificate, just use regular TLS\n");
	fprintf(stderr, "      interception. If they do provide a client certificate, forge all client\n");
	fprintf(stderr, "      certificate metadata and use the forged client certificate in the\n");
	fprintf(stderr, "      connection against the real server.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "    $ ratched --intercept www.johannes-bauer.com,c_certfile=joe.crt,c_keyfile=joe.key -o output.pcapng\n");
	fprintf(stderr, "      Same as before, but for connections to johannes-bauer.com, do not forge\n");
	fprintf(stderr, "      client certificates, but always use the given client certificate and key\n");
	fprintf(stderr, "      (joe.crt / joe.key) for authentication against the server.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "    $ ratched --keyspec ecc:secp256r1 --ocsp-uri http://www.ocsp-server.com -o output.pcapng\n");
	fprintf(stderr, "      Choose secp256r1 instead of RSA-2048 for all used certificates and\n");
	fprintf(stderr, "      encode an OCSP Responder URI into those forged certificates as well.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "    $ ratched --initial-read-timeout 5.0 --default intercept=mandatory -o output.pcapng\n");
	fprintf(stderr, "      Wait five seconds for connecting clients to send a valid ClientHello\n");
	fprintf(stderr, "      message. If after five seconds nothing is received or if unknown (non-\n");
	fprintf(stderr, "      TLS) traffic is received, terminate the connection instead of performing\n");
	fprintf(stderr, "      unmodified forwarding.\n");
	/* End of help page -- auto-generated, do not edit! */
	fprintf(stderr, "\n");
	fprintf(stderr, "   version " BUILD_REVISION " built on " BUILD_TIMESTAMP_UTC " UTC\n");
}

/* Begin of command definition enum -- auto-generated, do not edit! */
enum cmdline_arg_t {
	ARG_ERROR = '?',

	ARG_CONFIG_DIR_SHORT = 'c',
	ARG_LOCAL_FWD_SHORT = 'f',
	ARG_LISTEN_SHORT = 'l',
	ARG_DEFAULTS_SHORT = 'd',
	ARG_INTERCEPT_SHORT = 'i',
	ARG_OUTFILE_SHORT = 'o',
	ARG_VERBOSE_SHORT = 'v',

	ARG_CONFIG_DIR = 1000,
	ARG_LOCAL_FWD,
	ARG_SINGLE_SHOT,
	ARG_DUMP_CERTS,
	ARG_KEYSPEC,
	ARG_INITIAL_READ_TIMEOUT,
	ARG_MARK_FORGED_CERTIFICATES,
	ARG_NO_RECALCULATE_KEYIDS,
	ARG_DAEMONIZE,
	ARG_LOGFILE,
	ARG_FLUSH_LOGS,
	ARG_CRL_URI,
	ARG_OCSP_URI,
	ARG_WRITE_MEMDUMPS_INTO_FILES,
	ARG_USE_IPV6_ENCAPSULATION,
	ARG_LISTEN,
	ARG_DEFAULTS,
	ARG_INTERCEPT,
	ARG_PCAP_COMMENT,
	ARG_OUTFILE,
	ARG_VERBOSE,
};
/* End of command definition enum -- auto-generated, do not edit! */

static bool set_default_config_dir(void) {
	char *homedir = getenv("HOME");
	if (!homedir) {
		logmsg(LLVL_FATAL, "Could not determine $HOME directory.");
		return false;
	}
	const char *suffix = "/.config/ratched";
	pgm_options_rw.config_dir = malloc(strlen(homedir) + strlen(suffix) + 1);
	if (!pgm_options_rw.config_dir) {
		logmsg(LLVL_FATAL, "malloc(3) failed: %s", strerror(errno));
		return false;
	}
	strcpy(pgm_options_rw.config_dir, homedir);
	strcat(pgm_options_rw.config_dir, suffix);
	return true;
}

static bool parse_keyspec(const char *arg) {
	struct stringlist_t list;
	parse_stringlist(&list, arg, ":");
	if (list.token_cnt != 2) {
		snprintf(parsing_error, sizeof(parsing_error), "expected cryptosystem:parameters for keyspec, but got '%s'", arg);
		free_stringlist(&list);
		return false;
	}

	if (!strcmp(list.tokens[0], "rsa")) {
		const char *end = list.tokens[1];
		long int value = 0;
		if (!safe_strtol(&end, &value, false)) {
			snprintf(parsing_error, sizeof(parsing_error), "not a valid bitlength: '%s'", list.tokens[1]);
			free_stringlist(&list);
			return false;
		}
		if ((value < 256) || (value > 16384)) {
			snprintf(parsing_error, sizeof(parsing_error), "RSA bitlength must be between 256 and 16384 bits, got %ld", value);
			free_stringlist(&list);
			return false;
		}
		pgm_options_rw.keyspec.keytype = KEYTYPE_RSA;
		pgm_options_rw.keyspec.rsa.modulus_length_bits = value;
	} else if (!strcmp(list.tokens[0], "ecc")) {
		pgm_options_rw.keyspec.keytype = KEYTYPE_ECC;
		pgm_options_rw.keyspec.ecc.curvename = strdup(list.tokens[1]);
		if (!pgm_options_rw.keyspec.ecc.curvename) {
			logmsg(LLVL_FATAL, "strdup(3) failed: %s", strerror(errno));
			free_stringlist(&list);
			return false;
		}
	} else {
		snprintf(parsing_error, sizeof(parsing_error), "expected 'rsa' or 'ecc' as cryptosystem, but got '%s'", list.tokens[0]);
		free_stringlist(&list);
		return false;
	}
	free_stringlist(&list);
	return true;
}

static bool append_custom_intercept_config(const char *connection_params) {
	struct intercept_config_t *entry = intercept_config_new(connection_params, true);
	if (!entry) {
		return false;
	}
	if (strmap_has(pgm_options_rw.custom_configs, entry->hostname)) {
		snprintf(parsing_error, sizeof(parsing_error), "hostname '%s' specified at least twice.", entry->hostname);
		return false;
	}

	if (!strmap_set_ptr(pgm_options_rw.custom_configs, entry->hostname, entry)) {
		return false;
	}

	return true;
}

bool parse_options(int argc, char **argv) {
	pgm_options_rw.custom_configs = map_new();
	pgm_options_rw.network.server_socket.ipv4_nbo = htonl(IPv4ADDR(127, 0, 0, 1));
	pgm_options_rw.network.server_socket.port_nbo = htons(9999);

	/* Begin of command definition -- auto-generated, do not edit! */
	const char *short_options = "c:f:l:d:i:o:v";
	struct option long_options[] = {
		{ "config-dir",                  required_argument, 0, ARG_CONFIG_DIR },
		{ "local-fwd",                   required_argument, 0, ARG_LOCAL_FWD },
		{ "single-shot",                 no_argument,       0, ARG_SINGLE_SHOT },
		{ "dump-certs",                  no_argument,       0, ARG_DUMP_CERTS },
		{ "keyspec",                     required_argument, 0, ARG_KEYSPEC },
		{ "initial-read-timeout",        required_argument, 0, ARG_INITIAL_READ_TIMEOUT },
		{ "mark-forged-certificates",    no_argument,       0, ARG_MARK_FORGED_CERTIFICATES },
		{ "no-recalculate-keyids",       no_argument,       0, ARG_NO_RECALCULATE_KEYIDS },
		{ "daemonize",                   no_argument,       0, ARG_DAEMONIZE },
		{ "logfile",                     required_argument, 0, ARG_LOGFILE },
		{ "flush-logs",                  no_argument,       0, ARG_FLUSH_LOGS },
		{ "crl-uri",                     required_argument, 0, ARG_CRL_URI },
		{ "ocsp-uri",                    required_argument, 0, ARG_OCSP_URI },
		{ "write-memdumps-into-files",   no_argument,       0, ARG_WRITE_MEMDUMPS_INTO_FILES },
		{ "use-ipv6-encapsulation",      no_argument,       0, ARG_USE_IPV6_ENCAPSULATION },
		{ "listen",                      required_argument, 0, ARG_LISTEN },
		{ "defaults",                    required_argument, 0, ARG_DEFAULTS },
		{ "intercept",                   required_argument, 0, ARG_INTERCEPT },
		{ "pcap-comment",                required_argument, 0, ARG_PCAP_COMMENT },
		{ "outfile",                     required_argument, 0, ARG_OUTFILE },
		{ "verbose",                     no_argument,       0, ARG_VERBOSE },
		{ 0 }
	};
	/* End of command definition -- auto-generated, do not edit! */
	while (true) {
		int optval = getopt_long(argc, argv, short_options, long_options, NULL);
		if (optval == -1) {
			break;
		}
		enum cmdline_arg_t arg = (enum cmdline_arg_t)optval;
		switch (arg) {
			case ARG_CONFIG_DIR_SHORT:
			case ARG_CONFIG_DIR:
				pgm_options_rw.config_dir = strdup(optarg);
				if (!pgm_options_rw.config_dir) {
					logmsg(LLVL_FATAL, "strdup(3) failed: %s", strerror(errno));
					return false;
				}
				break;

			case ARG_LOCAL_FWD_SHORT:
			case ARG_LOCAL_FWD:
				if (!parse_hostname_port(optarg, &pgm_options_rw.network.local_forwarding.ipv4_nbo, &pgm_options_rw.network.local_forwarding.port_nbo)) {
					snprintf(parsing_error, sizeof(parsing_error), "not a valid hostname:port combination: %s", optarg);
					return false;
				}
				break;

			case ARG_SINGLE_SHOT:
				pgm_options_rw.operation.singleshot = true;
				break;

			case ARG_DUMP_CERTS:
				pgm_options_rw.log.dump_certificates = true;
				break;

			case ARG_KEYSPEC:
				if (!parse_keyspec(optarg)) {
					return false;
				}
				break;

			case ARG_INITIAL_READ_TIMEOUT:
				pgm_options_rw.network.initial_read_timeout = atof(optarg);
				if (pgm_options_rw.network.initial_read_timeout <= 0) {
					snprintf(parsing_error, sizeof(parsing_error), "read timeout must be a positive value");
					return false;
				}
				break;

			case ARG_MARK_FORGED_CERTIFICATES:
				pgm_options_rw.forged_certs.mark_forged_certificates = true;
				break;

			case ARG_NO_RECALCULATE_KEYIDS:
				pgm_options_rw.forged_certs.recalculate_key_identifiers = false;
				break;

			case ARG_DAEMONIZE:
				pgm_options_rw.operation.daemonize = true;
				break;

			case ARG_LOGFILE:
				pgm_options_rw.log.logfilename = optarg;
				break;

			case ARG_FLUSH_LOGS:
				pgm_options_rw.log.flush = true;
				break;

			case ARG_CRL_URI:
				pgm_options_rw.forged_certs.crl_uri = optarg;
				break;

			case ARG_OCSP_URI:
				pgm_options_rw.forged_certs.ocsp_responder_uri = optarg;
				break;

			case ARG_WRITE_MEMDUMPS_INTO_FILES:
				pgm_options_rw.log.write_memdumps_into_files = true;
				break;

			case ARG_USE_IPV6_ENCAPSULATION:
				pgm_options_rw.pcapng.use_ipv6_encapsulation = true;
				break;

			case ARG_LISTEN_SHORT:
			case ARG_LISTEN:
				if (!parse_hostname_port(optarg, &pgm_options_rw.network.server_socket.ipv4_nbo, &pgm_options_rw.network.server_socket.port_nbo)) {
					snprintf(parsing_error, sizeof(parsing_error), "not a valid hostname:port combination: %s", optarg);
					return false;
				}
				break;

			case ARG_DEFAULTS_SHORT:
			case ARG_DEFAULTS:
				if (pgm_options_rw.default_config) {
					snprintf(parsing_error, sizeof(parsing_error), "default configuration can only be supplied once");
					return false;
				}
				pgm_options_rw.default_config = intercept_config_new(optarg, false);
				if (!pgm_options_rw.default_config) {
					return false;
				}
				break;

			case ARG_INTERCEPT_SHORT:
			case ARG_INTERCEPT:
				if (!append_custom_intercept_config(optarg)) {
					return false;
				}
				break;

			case ARG_PCAP_COMMENT:
				pgm_options_rw.pcapng.comment = optarg;
				break;

			case ARG_OUTFILE_SHORT:
			case ARG_OUTFILE:
				pgm_options_rw.pcapng.filename = optarg;
				break;

			case ARG_VERBOSE_SHORT:
			case ARG_VERBOSE:
				pgm_options_rw.log.level++;
				break;

			case ARG_ERROR:
				return false;
		}
	}
	if (optind != argc) {
		snprintf(parsing_error, sizeof(parsing_error), "superfluous positional arguments given");
		return false;
	}
	if (!pgm_options_rw.config_dir) {
		if (!set_default_config_dir()) {
			return false;
		}
	}
	if (!pgm_options_rw.pcapng.filename) {
		snprintf(parsing_error, sizeof(parsing_error), "no output file was given");
		return false;
	}
	return true;
}

static void freenull(char **argument) {
	free(*argument);
	*argument = NULL;
}

static void free_intercept_config_void(void *intercept_config) {
	intercept_config_free((struct intercept_config_t*)intercept_config);
}

void free_pgm_options(void) {
	freenull(&pgm_options_rw.config_dir);

	intercept_config_free(pgm_options_rw.default_config);
	map_foreach_ptrvalue(pgm_options_rw.custom_configs, free_intercept_config_void);
	map_free(pgm_options_rw.custom_configs);

	if ((pgm_options_rw.keyspec.keytype == KEYTYPE_ECC) && pgm_options_rw.keyspec.ecc.curvename) {
		freenull(&pgm_options_rw.keyspec.ecc.curvename);
	}
}
