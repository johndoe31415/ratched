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
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include "logging.h"
#include "tcpip.h"
#include "pcapng.h"
#include "ipfwd.h"

#define IPv4_VERSION_IHL_DEFAULT	0x45
#define IPv4_PROTOCOL_TCP			6
#define TCP_DATA_OFFSET_DEFAULT		0x50

#define TCP_FLAG_FIN		(1 << 0)
#define TCP_FLAG_SYN		(1 << 1)
#define TCP_FLAG_RST		(1 << 2)
#define TCP_FLAG_PSH		(1 << 3)
#define TCP_FLAG_ACK		(1 << 4)
#define TCP_FLAG_URG		(1 << 5)
#define TCP_FLAG_ECN		(1 << 6)
#define TCP_FLAG_CWR		(1 << 7)

struct ipv4_hdr_t {
	uint8_t version_ihl;
	uint8_t tos;
	uint16_t total_length;
	uint16_t identification;
	uint16_t flags_frag_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t header_checksum;
	uint32_t source_ip;
	uint32_t destination_ip;
} __attribute__ ((packed));

struct ipv6_hdr_t {
	uint32_t version_tc_flow_label;
	uint16_t payload_length;
	uint8_t next_header;
	uint8_t hop_limit;
	uint8_t source_ip6[16];
	uint8_t destination_ip6[16];
} __attribute__ ((packed));

struct tcp_hdr_t {
	uint16_t source_port;
	uint16_t destination_port;
	uint32_t seq_no;
	uint32_t ack_no;
	uint8_t data_offset;
	uint8_t flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_ptr;
} __attribute__ ((packed));

struct packet4_t {
	struct ipv4_hdr_t ipv4;
	struct tcp_hdr_t tcp;
	uint8_t payload[];
} __attribute__ ((packed));

struct packet6_t {
	struct ipv6_hdr_t ipv6;
	struct tcp_hdr_t tcp;
	uint8_t payload[];
} __attribute__ ((packed));

union packet_t {
	struct packet4_t pkt4;
	struct packet6_t pkt6;
};

static void set_tcp_header(struct tcp_hdr_t *tcp, uint8_t tcp_flags) {
	tcp->data_offset = TCP_DATA_OFFSET_DEFAULT;
	tcp->window = htons(16 * 1024);
	tcp->flags = tcp_flags;
}

static int set_tcp_ip6_header(struct packet6_t *pkt, int payload_length, const char *comment, uint8_t tcp_flags) {
	int total_length = sizeof(struct packet6_t) + payload_length;
	pkt->ipv6.version_tc_flow_label = htonl(0x60000000);
	pkt->ipv6.payload_length = htons(sizeof(struct tcp_hdr_t) + payload_length);
	pkt->ipv6.next_header = IPv4_PROTOCOL_TCP;
	pkt->ipv6.hop_limit = 10;
	set_tcp_header(&pkt->tcp, tcp_flags);
	return total_length;
}

static int set_tcp_ip4_header(struct packet4_t *pkt, int payload_length, const char *comment, uint8_t tcp_flags) {
	int total_length = sizeof(struct packet4_t) + payload_length;
	pkt->ipv4.version_ihl = IPv4_VERSION_IHL_DEFAULT;
	pkt->ipv4.total_length = htons(total_length);
	pkt->ipv4.protocol = IPv4_PROTOCOL_TCP;
	pkt->ipv4.ttl = 10;
	set_tcp_header(&pkt->tcp, tcp_flags);
	return total_length;
}

static void write_tcp_ip_packet(struct connection_t *conn, union packet_t *pkt, int payload_length, uint8_t tcp_flags, const char *comment) {
	int total_length = 0;
	const void *pktbuf = NULL;
	if (!conn->ipv6_encapsulation) {
		total_length = set_tcp_ip4_header(&pkt->pkt4, payload_length, comment, tcp_flags);
		pktbuf = &pkt->pkt4;
	} else {
		total_length = set_tcp_ip6_header(&pkt->pkt6, payload_length, comment, tcp_flags);
		pktbuf = &pkt->pkt6;
	}
	pcapng_write_epb(conn->mtdump->f, pktbuf, total_length, comment);
}

static void tcp_load_packet_address(struct tcp_hdr_t *tcp, struct connection_t *conn, bool direction, int payload_len) {
	if (direction) {
		tcp->source_port = conn->connector.port_nbo;
		tcp->destination_port = conn->acceptor.port_nbo;
		tcp->seq_no = htonl(conn->connector.seqno);
		tcp->ack_no = htonl(conn->acceptor.seqno);
		conn->connector.seqno += payload_len;
	} else {
		tcp->source_port = conn->acceptor.port_nbo;
		tcp->destination_port = conn->connector.port_nbo;
		tcp->seq_no = htonl(conn->acceptor.seqno);
		tcp->ack_no = htonl(conn->connector.seqno);
		conn->acceptor.seqno += payload_len;
	}
}

static void ipv4_load_packet_address(struct packet4_t *pkt, struct connection_t *conn, bool direction, int payload_len) {
	if (direction) {
		pkt->ipv4.source_ip = conn->connector.ip_nbo;
		pkt->ipv4.destination_ip = conn->acceptor.ip_nbo;
	} else {
		pkt->ipv4.source_ip = conn->acceptor.ip_nbo;
		pkt->ipv4.destination_ip = conn->connector.ip_nbo;
	}
	tcp_load_packet_address(&pkt->tcp, conn, direction, payload_len);
}

static void ipv6_load_packet_address(struct packet6_t *pkt, struct connection_t *conn, bool direction, int payload_len) {
	/* Use 6to4 encapsulation */
	memset(pkt->ipv6.source_ip6, 0, 16);
	memset(pkt->ipv6.destination_ip6, 0, 16);


	uint32_t connector_ip = ntohl(conn->connector.ip_nbo);
	uint32_t acceptor_ip = ntohl(conn->acceptor.ip_nbo);
	if (direction) {
		pkt->ipv6.source_ip6[0] = 0x20;
		pkt->ipv6.source_ip6[1] = 0x02;
		pkt->ipv6.source_ip6[2] = (connector_ip >> 24) & 0xff;
		pkt->ipv6.source_ip6[3] = (connector_ip >> 16) & 0xff;
		pkt->ipv6.source_ip6[4] = (connector_ip >> 8) & 0xff;
		pkt->ipv6.source_ip6[5] = (connector_ip >> 0) & 0xff;
		pkt->ipv6.source_ip6[6] = (conn->connector.hostname_id >> 8) & 0xff;
		pkt->ipv6.source_ip6[7] = (conn->connector.hostname_id >> 0) & 0xff;

		pkt->ipv6.destination_ip6[0] = 0x20;
		pkt->ipv6.destination_ip6[1] = 0x02;
		pkt->ipv6.destination_ip6[2] = (acceptor_ip >> 24) & 0xff;
		pkt->ipv6.destination_ip6[3] = (acceptor_ip >> 16) & 0xff;
		pkt->ipv6.destination_ip6[4] = (acceptor_ip >> 8) & 0xff;
		pkt->ipv6.destination_ip6[5] = (acceptor_ip >> 0) & 0xff;
		pkt->ipv6.destination_ip6[6] = (conn->acceptor.hostname_id >> 8) & 0xff;
		pkt->ipv6.destination_ip6[7] = (conn->acceptor.hostname_id >> 0) & 0xff;
	} else {
		pkt->ipv6.source_ip6[0] = 0x20;
		pkt->ipv6.source_ip6[1] = 0x02;
		pkt->ipv6.source_ip6[2] = (acceptor_ip >> 24) & 0xff;
		pkt->ipv6.source_ip6[3] = (acceptor_ip >> 16) & 0xff;
		pkt->ipv6.source_ip6[4] = (acceptor_ip >> 8) & 0xff;
		pkt->ipv6.source_ip6[5] = (acceptor_ip >> 0) & 0xff;
		pkt->ipv6.source_ip6[6] = (conn->acceptor.hostname_id >> 8) & 0xff;
		pkt->ipv6.source_ip6[7] = (conn->acceptor.hostname_id >> 0) & 0xff;

		pkt->ipv6.destination_ip6[0] = 0x20;
		pkt->ipv6.destination_ip6[1] = 0x02;
		pkt->ipv6.destination_ip6[2] = (connector_ip >> 24) & 0xff;
		pkt->ipv6.destination_ip6[3] = (connector_ip >> 16) & 0xff;
		pkt->ipv6.destination_ip6[4] = (connector_ip >> 8) & 0xff;
		pkt->ipv6.destination_ip6[5] = (connector_ip >> 0) & 0xff;
		pkt->ipv6.destination_ip6[6] = (conn->connector.hostname_id >> 8) & 0xff;
		pkt->ipv6.destination_ip6[7] = (conn->connector.hostname_id >> 0) & 0xff;
	}
	tcp_load_packet_address(&pkt->tcp, conn, direction, payload_len);
}

static void tcpip_load_packet_address(union packet_t *pkt, struct connection_t *conn, bool direction, int payload_len) {
	if (!conn->ipv6_encapsulation) {
		ipv4_load_packet_address(&pkt->pkt4, conn, direction, payload_len);
	} else {
		ipv6_load_packet_address(&pkt->pkt6, conn, direction, payload_len);
	}
}

void create_tcp_ip_connection(struct multithread_dumper_t *mtdump, struct connection_t *conn, const char *comment, bool use_ipv6_encapsulation) {
	union packet_t pkt;
	memset(&pkt, 0, sizeof(pkt));

	pthread_mutex_lock(&mtdump->mutex);

	conn->mtdump = mtdump;
	conn->ipv6_encapsulation = use_ipv6_encapsulation;

	tcpip_load_packet_address(&pkt, conn, true, 1);
	if (!conn->ipv6_encapsulation) {
		if (conn->connector.hostname) {
			pcapng_write_nrb(mtdump->f, &conn->connector.ip_nbo, conn->connector.hostname, true);
		}
		if (conn->acceptor.hostname) {
			pcapng_write_nrb(mtdump->f, &conn->acceptor.ip_nbo, conn->acceptor.hostname, true);
		}
	} else {
		if (conn->connector.hostname) {
			pcapng_write_nrb(mtdump->f, pkt.pkt6.ipv6.source_ip6, conn->connector.hostname, false);
		} else {
			/* If we don't have an IPv6 hostname, we transcribe the IPv4
			 * address as "hostname" for nice display in Wireshark */
			char ipv4[16];
			snprintf(ipv4, sizeof(ipv4), PRI_IPv4, FMT_IPv4(conn->connector.ip_nbo));
			pcapng_write_nrb(mtdump->f, pkt.pkt6.ipv6.source_ip6, ipv4, false);
		}
		if (conn->acceptor.hostname) {
			pcapng_write_nrb(mtdump->f, pkt.pkt6.ipv6.destination_ip6, conn->acceptor.hostname, false);
		} else {
			/* If we don't have an IPv6 hostname, we transcribe the IPv4
			 * address as "hostname" for nice display in Wireshark */
			char ipv4[16];
			snprintf(ipv4, sizeof(ipv4), PRI_IPv4, FMT_IPv4(conn->acceptor.ip_nbo));
			pcapng_write_nrb(mtdump->f, pkt.pkt6.ipv6.destination_ip6, ipv4, false);
		}
	}
	write_tcp_ip_packet(conn, &pkt, 0, TCP_FLAG_SYN, comment);

	tcpip_load_packet_address(&pkt, conn, false, 1);
	write_tcp_ip_packet(conn, &pkt, 0, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL);

	tcpip_load_packet_address(&pkt, conn, true, 0);
	write_tcp_ip_packet(conn, &pkt, 0, TCP_FLAG_ACK, NULL);
	pthread_mutex_unlock(&mtdump->mutex);
}

void append_tcp_ip_data(struct connection_t *conn, bool direction, const uint8_t *payload, int payload_len) {
	uint8_t pktbuf[sizeof(union packet_t) + payload_len];
	union packet_t *pkt = (union packet_t*)pktbuf;
	memset(pktbuf, 0, sizeof(pktbuf));

	if (!conn->ipv6_encapsulation) {
		memcpy(&pkt->pkt4.payload, payload, payload_len);
	} else {
		memcpy(&pkt->pkt6.payload, payload, payload_len);
	}

	pthread_mutex_lock(&conn->mtdump->mutex);
	tcpip_load_packet_address(pkt, conn, direction, payload_len);
	write_tcp_ip_packet(conn, pkt, payload_len, 0, NULL);

	tcpip_load_packet_address(pkt, conn, !direction, 0);
	write_tcp_ip_packet(conn, pkt, 0, TCP_FLAG_ACK, NULL);
	pthread_mutex_unlock(&conn->mtdump->mutex);
}

void append_tcp_ip_string(struct connection_t *conn, bool direction, const char *string) {
	append_tcp_ip_data(conn, direction, (const uint8_t*)string, strlen(string));
}

void teardown_tcp_ip_connection(struct connection_t *conn, bool direction) {
	union packet_t pkt;
	memset(&pkt, 0, sizeof(pkt));

	pthread_mutex_lock(&conn->mtdump->mutex);
	tcpip_load_packet_address(&pkt, conn, direction, 1);
	write_tcp_ip_packet(conn, &pkt, 0, TCP_FLAG_FIN, NULL);

	tcpip_load_packet_address(&pkt, conn, !direction, 1);
	write_tcp_ip_packet(conn, &pkt, 0, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL);

	tcpip_load_packet_address(&pkt, conn, direction, 0);
	write_tcp_ip_packet(conn, &pkt, 0, TCP_FLAG_ACK, NULL);
	pthread_mutex_unlock(&conn->mtdump->mutex);
}

bool open_pcap_write(struct multithread_dumper_t *mtdump, const char *filename, const char *comment) {
	memset(mtdump, 0, sizeof(struct multithread_dumper_t));
	pthread_mutex_init(&mtdump->mutex, NULL);

	mtdump->f = pcapng_open(filename, LINKTYPE_RAW, 65535, comment);
	if (!mtdump->f) {
		logmsg(LLVL_ERROR, "Error opening %s for writing: %s", filename, strerror(errno));
		pthread_mutex_destroy(&mtdump->mutex);
		return false;
	}
	return true;
}

bool close_pcap(struct multithread_dumper_t *mtdump) {
	fclose(mtdump->f);
	pthread_mutex_destroy(&mtdump->mutex);
	return true;
}
