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
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <sys/time.h>
#include "logging.h"
#include "pcapng.h"

#define MAX_OPTION_CNT					16

#define PCAPNG_BLOCKTYPE_SHB			0x0A0D0D0A
#define PCAPNG_BLOCKTYPE_IDB			1
#define PCAPNG_BLOCKTYPE_NRB			4
#define PCAPNG_BLOCKTYPE_EPB			6

#define OPTIONCODE_ENDOFOPT				0
#define OPTIONCODE_COMMENT				1

#define OPTIONCODE_IDB_IF_NAME			2
#define OPTIONCODE_IDB_IF_DESCRIPTION	3
#define OPTIONCODE_IDB_IF_IPv4ADDR		4
#define OPTIONCODE_IDB_IF_IPv6ADDR		5
#define OPTIONCODE_IDB_IF_MACADDR		6
#define OPTIONCODE_IDB_IF_EUIADDR		7
#define OPTIONCODE_IDB_IF_SPEED			8
#define OPTIONCODE_IDB_IF_TSRESOL		9
#define OPTIONCODE_IDB_IF_TZONE			10
#define OPTIONCODE_IDB_IF_FILTER		11
#define OPTIONCODE_IDB_IF_OS			12
#define OPTIONCODE_IDB_IF_FCSLEN		13
#define OPTIONCODE_IDB_IF_TSOFFSET		14

#define OPTIONCODE_ISB_STARTTIME		2
#define OPTIONCODE_ISB_ENDTIME			3
#define OPTIONCODE_ISB_IFRECV			4
#define OPTIONCODE_ISB_IFDROP			5
#define OPTIONCODE_ISB_FILTERACCEPT		6
#define OPTIONCODE_ISB_OSDROP			7
#define OPTIONCODE_ISB_USRDELIV			8

#define NRB_RECORD_END					0
#define NRB_RECORD_IPv4					1
#define NRV_RECORD_IPv6					2

#define ROUND_UP(x)					((((x) + 3) / 4) * 4)

struct pcapng_block_hdr_t {
	uint32_t blocktype;
	uint32_t blocklength;
} __attribute__ ((packed));

struct pcapng_option_t {
	uint16_t code;
	uint16_t length;
	uint8_t data[];
} __attribute__ ((packed));

struct pcapng_namerecord_t {
	uint16_t rectype;
	uint16_t length;
	char data[];
} __attribute__ ((packed));

struct pcapng_option_list_t {
	int option_cnt;
	struct pcapng_option_t *options[MAX_OPTION_CNT];
};

struct pcapng_shb_t {
	struct pcapng_block_hdr_t hdr;
	uint32_t byteorder_magic;
	uint16_t major;
	uint16_t minor;
	uint64_t sectionlength;
} __attribute__ ((packed));

struct pcapng_idb_t {
	struct pcapng_block_hdr_t hdr;
	uint16_t linktype;
	uint16_t reserved;
	uint32_t snaplen;
} __attribute__ ((packed));

struct pcapng_epb_t {
	struct pcapng_block_hdr_t hdr;
	uint32_t iface_id;
	uint32_t ts_high;
	uint32_t ts_low;
	uint32_t cap_length;
	uint32_t orig_length;
} __attribute__ ((packed));

static void pcapng_option_list_new(struct pcapng_option_list_t *list) {
	memset(list, 0, sizeof(struct pcapng_option_list_t));
}

static bool pcapng_option_list_add(struct pcapng_option_list_t *list, uint16_t code, uint16_t length, const uint8_t *data) {
	if (list->option_cnt == MAX_OPTION_CNT) {
		return false;
	}

	int alloc_size = ROUND_UP(sizeof(struct pcapng_option_t) + length);
	list->options[list->option_cnt] = calloc(alloc_size, 1);
	if (!list->options[list->option_cnt]) {
		return false;
	}
	list->options[list->option_cnt]->code = code;
	list->options[list->option_cnt]->length = length;
	if (data) {
		memcpy(list->options[list->option_cnt]->data, data, length);
	}
	list->option_cnt++;
	return true;
}

static void pcapng_option_list_free(struct pcapng_option_list_t *list) {
	for (int i = 0; i < list->option_cnt; i++) {
		free(list->options[i]);
	}
	list->option_cnt = 0;
}

static int determine_option_size(const struct pcapng_option_list_t *list) {
	int option_size_bytes = 0;
	if (list && (list->option_cnt > 0)) {
		for (int i = 0; i < list->option_cnt; i++) {
			int option_size_padded = ROUND_UP(sizeof(struct pcapng_option_t) + list->options[i]->length);
			option_size_bytes += option_size_padded;
		}
		/* Add space for "end of list" option */
		option_size_bytes += 4;
	}
	return option_size_bytes;
}

static bool write_option_block(FILE *f, const struct pcapng_option_list_t *list) {
	if (list->option_cnt == 0) {
		/* Don't write an empty option block */
		return true;
	}

	for (int i = 0; i < list->option_cnt; i++) {
		int option_size_padded = ROUND_UP(sizeof(struct pcapng_option_t) + list->options[i]->length);
		if (fwrite(list->options[i], option_size_padded, 1, f) != 1) {
			return false;
		}
	}
	/* End of list */
	struct pcapng_option_t end_of_list_option = {
		.code = OPTIONCODE_ENDOFOPT,
		.length = 0,
	};
	if (fwrite(&end_of_list_option, sizeof(end_of_list_option), 1, f) != 1) {
		return false;
	}
	return true;
}

static bool pcapng_write_block(FILE *f, struct pcapng_block_hdr_t *block, unsigned int static_len, const struct pcapng_option_list_t *list) {
	block->blocklength = static_len + determine_option_size(list) + 4;
	if (fwrite(block, static_len, 1, f) != 1) {
		return false;
	}
	if (list && !write_option_block(f, list)) {
		return false;
	}
	if (fwrite(&block->blocklength, sizeof(uint32_t), 1, f) != 1) {
		return false;
	}
	return true;
}

bool pcapng_write_shb(FILE *f, const char *comment) {
	struct pcapng_shb_t block = {
		.hdr = {
			.blocktype = PCAPNG_BLOCKTYPE_SHB,
		},
		.byteorder_magic = 0x1A2B3C4D,
		.major = 1,
		.minor = 0,
		.sectionlength = -1,
	};


	struct pcapng_option_list_t list;
	pcapng_option_list_new(&list);
	if (comment) {
		pcapng_option_list_add(&list, OPTIONCODE_COMMENT, strlen(comment), (const uint8_t*)comment);
	}
	bool success = pcapng_write_block(f, (struct pcapng_block_hdr_t*)&block, sizeof(struct pcapng_shb_t), &list);
	pcapng_option_list_free(&list);
	return success;
}


bool pcapng_write_idb(FILE *f, uint16_t linktype, uint32_t snaplen, const char *ifname, const char *ifdesc) {
	struct pcapng_idb_t block = {
		.hdr = {
			.blocktype = PCAPNG_BLOCKTYPE_IDB,
		},
		.linktype = linktype,
		.snaplen = snaplen,
	};
	struct pcapng_option_list_t list;
	pcapng_option_list_new(&list);
	uint8_t resolution = 6;		// each tick is 10^-6 seconds
	pcapng_option_list_add(&list, OPTIONCODE_IDB_IF_TSRESOL, 1, &resolution);
	if (ifname) {
		pcapng_option_list_add(&list, OPTIONCODE_IDB_IF_NAME, strlen(ifname), (const uint8_t*)ifname);
	}
	if (ifdesc) {
		pcapng_option_list_add(&list, OPTIONCODE_IDB_IF_DESCRIPTION, strlen(ifdesc), (const uint8_t*)ifdesc);
	}
	bool success = pcapng_write_block(f, (struct pcapng_block_hdr_t*)&block, sizeof(struct pcapng_idb_t), &list);
	pcapng_option_list_free(&list);
	return success;
}

bool pcapng_write_nrb_ipv4(FILE *f, const uint32_t ipv4_nbo, const char *hostname) {
	int hlen = strlen(hostname) + 1;
	struct pcapng_block_hdr_t hdr = {
		.blocktype = PCAPNG_BLOCKTYPE_NRB,
		.blocklength = sizeof(hdr) + sizeof(struct pcapng_namerecord_t) + 4 + ROUND_UP(hlen) + 4 + 4,
	};
	if (fwrite(&hdr, sizeof(hdr), 1, f) != 1) {
		return false;
	}

	struct pcapng_namerecord_t namerecord = {
		.rectype = NRB_RECORD_IPv4,
		.length = 4 + hlen,
	};
	if (fwrite(&namerecord, sizeof(namerecord), 1, f) != 1) {
		return false;
	}
	for (int i = 0; i < 4; i++) {
		if (fwrite(((uint8_t*)&ipv4_nbo) + i, sizeof(uint8_t), 1, f) != 1) {
			return false;
		}
	}
	if (fwrite(hostname, hlen, 1, f) != 1) {
		return false;
	}
	int hostname_length_padding = 4 - (hlen % 4);
	if (hostname_length_padding < 4) {
		uint32_t padding = 0;
		if (fwrite(&padding, hostname_length_padding, 1, f) != 1) {
			return false;
		}
	}

	struct pcapng_namerecord_t end_of_namerecord = {
		.rectype = NRB_RECORD_END,
		.length = 0,
	};
	if (fwrite(&end_of_namerecord, sizeof(end_of_namerecord), 1, f) != 1) {
		return false;
	}

	if (fwrite(&hdr.blocklength, sizeof(uint32_t), 1, f) != 1) {
		return false;
	}
	return true;
}

bool pcapng_write_epb(FILE *f, const uint8_t *payload, unsigned int payload_length, const char *comment) {
	struct pcapng_option_list_t list;
	pcapng_option_list_new(&list);
	if (comment) {
		pcapng_option_list_add(&list, OPTIONCODE_COMMENT, strlen(comment), (const uint8_t*)comment);
	}

	struct timeval tv;
	if (gettimeofday(&tv, NULL) == -1) {
		logmsg(LLVL_ERROR, "Could not gettimeofday(): %s", strerror(errno));
		return false;
	}
	uint64_t time_usec = (1000000 * (uint64_t)tv.tv_sec) + tv.tv_usec;
	struct pcapng_epb_t block = {
		.hdr = {
			.blocktype = PCAPNG_BLOCKTYPE_EPB,
			.blocklength = sizeof(block) + ROUND_UP(payload_length) + 4,
		},
		.ts_high = (time_usec >> 32) & 0xffffffff,
		.ts_low = (time_usec >> 0) & 0xffffffff,
		.cap_length = payload_length,
		.orig_length = payload_length,
	};
	block.hdr.blocklength = sizeof(block) + ROUND_UP(payload_length) + determine_option_size(&list) + 4;

	if (fwrite(&block, sizeof(block), 1, f) != 1) {
		pcapng_option_list_free(&list);
		return false;
	}
	if (fwrite(payload, payload_length, 1, f) != 1) {
		pcapng_option_list_free(&list);
		return false;
	}

	int payload_length_padding = 4 - (payload_length % 4);
	if (payload_length_padding < 4) {
		uint32_t padding = 0;
		if (fwrite(&padding, payload_length_padding, 1, f) != 1) {
			pcapng_option_list_free(&list);
			return false;
		}
	}

	if (!write_option_block(f, &list)) {
		pcapng_option_list_free(&list);
		return false;
	}

	if (fwrite(&block.hdr.blocklength, sizeof(uint32_t), 1, f) != 1) {
		pcapng_option_list_free(&list);
		return false;
	}
	pcapng_option_list_free(&list);
	return true;
}

FILE *pcapng_open(const char *filename, uint16_t linktype, uint32_t snaplen, const char *comment) {
	FILE *f = fopen(filename, "w");
	if (!f) {
		return NULL;
	}
	pcapng_write_shb(f, comment);
	pcapng_write_idb(f, linktype, snaplen, NULL, NULL);
	return f;
}
