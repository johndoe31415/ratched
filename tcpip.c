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

struct packet_t {
	struct ipv4_hdr_t ipv4;
	struct tcp_hdr_t tcp;
	uint8_t payload[];
} __attribute__ ((packed));

static void write_tcp_ip_packet(struct multithread_dumper_t *mtdump, struct packet_t *pkt, int payload_length, const char *comment) {
	int total_length = sizeof(struct packet_t) + payload_length;
	pkt->ipv4.version_ihl = IPv4_VERSION_IHL_DEFAULT;
	pkt->ipv4.total_length = htons(total_length);
	pkt->ipv4.protocol = IPv4_PROTOCOL_TCP;
	pkt->ipv4.ttl = 10;
	pkt->tcp.data_offset = TCP_DATA_OFFSET_DEFAULT;
	pkt->tcp.window = htons(16 * 1024);
	pcapng_write_epb(mtdump->f, (const uint8_t*)pkt, total_length, comment);
}

static void swap_uint16(uint16_t *a, uint16_t *b) {
	uint16_t x;
	x = *a;
	*a = *b;
	*b = x;
}

static void swap_uint32(uint32_t *a, uint32_t *b) {
	uint32_t x;
	x = *a;
	*a = *b;
	*b = x;
}

static void pkt_reverse_flow(struct packet_t *pkt) {
	swap_uint16(&pkt->tcp.source_port, &pkt->tcp.destination_port);
	swap_uint32(&pkt->ipv4.source_ip, &pkt->ipv4.destination_ip);
	swap_uint32(&pkt->tcp.seq_no, &pkt->tcp.ack_no);
}

static void load_packet_address(struct packet_t *pkt, struct connection_t *conn, bool direction, int payload_len) {
	if (direction) {
		pkt->ipv4.source_ip = conn->connector.ip_nbo;
		pkt->ipv4.destination_ip = conn->acceptor.ip_nbo;
		pkt->tcp.source_port = conn->connector.port_nbo;
		pkt->tcp.destination_port = conn->acceptor.port_nbo;
		pkt->tcp.seq_no = htonl(conn->connector.seqno);
		pkt->tcp.ack_no = htonl(conn->acceptor.seqno);
		conn->connector.seqno += payload_len;
	} else {
		pkt->ipv4.source_ip = conn->acceptor.ip_nbo;
		pkt->ipv4.destination_ip = conn->connector.ip_nbo;
		pkt->tcp.source_port = conn->acceptor.port_nbo;
		pkt->tcp.destination_port = conn->connector.port_nbo;
		pkt->tcp.seq_no = htonl(conn->acceptor.seqno);
		pkt->tcp.ack_no = htonl(conn->connector.seqno);
		conn->acceptor.seqno += payload_len;
	}
}

void create_tcp_ip_connection(struct multithread_dumper_t *mtdump, struct connection_t *conn, const char *comment) {
	struct packet_t pkt;
	memset(&pkt, 0, sizeof(pkt));

	pthread_mutex_lock(&mtdump->mutex);

	if (conn->connector.hostname) {
		pcapng_write_nrb_ipv4(mtdump->f, conn->connector.ip_nbo, conn->connector.hostname);
	}
	if (conn->acceptor.hostname) {
		pcapng_write_nrb_ipv4(mtdump->f, conn->acceptor.ip_nbo, conn->acceptor.hostname);
	}

	pkt.ipv4.source_ip = conn->connector.ip_nbo;
	pkt.ipv4.destination_ip = conn->acceptor.ip_nbo;
	pkt.tcp.source_port = conn->connector.port_nbo;
	pkt.tcp.destination_port = conn->acceptor.port_nbo;
	pkt.tcp.flags = TCP_FLAG_SYN;
	write_tcp_ip_packet(mtdump, &pkt, 0, comment);

	pkt_reverse_flow(&pkt);
	pkt.tcp.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
	pkt.tcp.ack_no = htonl(1);
	write_tcp_ip_packet(mtdump, &pkt, 0, NULL);

	pkt_reverse_flow(&pkt);
	pkt.tcp.flags = TCP_FLAG_ACK;
	pkt.tcp.ack_no = htonl(1);
	write_tcp_ip_packet(mtdump, &pkt, 0, NULL);
	pthread_mutex_unlock(&mtdump->mutex);

	conn->connector.seqno = 1;
	conn->acceptor.seqno = 1;
	conn->mtdump = mtdump;
}

void append_tcp_ip_data(struct connection_t *conn, bool direction, const uint8_t *payload, int payload_len) {
	uint8_t pktbuf[sizeof(struct packet_t) + payload_len];
	struct packet_t *pkt = (struct packet_t*)pktbuf;
	memset(pkt, 0, sizeof(pktbuf));
	memcpy(pkt->payload, payload, payload_len);

	pthread_mutex_lock(&conn->mtdump->mutex);

	load_packet_address(pkt, conn, direction, payload_len);
	write_tcp_ip_packet(conn->mtdump, pkt, payload_len, NULL);

	load_packet_address(pkt, conn, !direction, 0);
	pkt->tcp.flags = TCP_FLAG_ACK;
	write_tcp_ip_packet(conn->mtdump, pkt, 0, NULL);
	pthread_mutex_unlock(&conn->mtdump->mutex);
}

void teardown_tcp_ip_connection(struct connection_t *conn, bool direction) {
	struct packet_t pkt;
	memset(&pkt, 0, sizeof(pkt));

	pthread_mutex_lock(&conn->mtdump->mutex);
	load_packet_address(&pkt, conn, direction, 1);
	pkt.tcp.flags = TCP_FLAG_FIN;
	write_tcp_ip_packet(conn->mtdump, &pkt, 0, NULL);

	load_packet_address(&pkt, conn, !direction, 1);
	pkt.tcp.flags = TCP_FLAG_FIN | TCP_FLAG_ACK;
	write_tcp_ip_packet(conn->mtdump, &pkt, 0, NULL);

	load_packet_address(&pkt, conn, direction, 0);
	pkt.tcp.flags = TCP_FLAG_ACK;
	write_tcp_ip_packet(conn->mtdump, &pkt, 0, NULL);
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
