#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "logging.h"
#include "datafilter.h"

struct filterdata_sink_t {
	filter_sink_fnc_t sink_fnc;
	void *sink_fnc_arg;
};

static bool filterfnc_sink_new(void *data, void *init_attrs) {
	struct filterdata_sink_t *ctx = (struct filterdata_sink_t*)data;
	struct filterdata_sink_t *attr = (struct filterdata_sink_t*)init_attrs;
	*ctx = *attr;
	return true;
}

static void filterfnc_sink_put(struct datafilter_t *filter, const uint8_t *data, unsigned int length) {
	struct filterdata_sink_t *ctx = (struct filterdata_sink_t *)filter->data;
	ctx->sink_fnc(ctx->sink_fnc_arg, data, length);
}

static const struct filterclass_t filterclass_sink = {
	.name = "sink",
	.datasize = sizeof(struct filterdata_sink_t),
	.flt_new = filterfnc_sink_new,
	.flt_put = filterfnc_sink_put,
};

struct datafilter_t *datafilter_new(const struct filterclass_t *flt_class, void *flt_init_args, struct datafilter_t *next) {
	struct datafilter_t *filter = calloc(sizeof(struct datafilter_t), 1);
	if (!filter) {
		logmsg(LLVL_FATAL, "Failed to calloc(3) memory for data filter: %s", strerror(errno));
		return NULL;
	}
	filter->flt_class = flt_class;
	filter->next = next;
	if (filter->flt_class->datasize) {
		filter->data = calloc(1, filter->flt_class->datasize);
		if (!filter->data) {
			logmsg(LLVL_FATAL, "Failed to calloc(3) %d bytes of data memory for '%s' type data filter: %s", filter->flt_class->datasize, filter->flt_class->name, strerror(errno));
			free(filter);
			return NULL;
		}
	}
	if (filter->flt_class->flt_new) {
		if (!filter->flt_class->flt_new(filter->data, flt_init_args)) {
			logmsg(LLVL_FATAL, "Failed to calloc(3) internal memory for '%s' type data filter: %s", filter->flt_class->name, strerror(errno));
			free(filter->data);
			free(filter);
			return NULL;
		}
	}
	return filter;
}

struct datafilter_t *datafilter_new_sink(filter_sink_fnc_t sink_fnc, void *sink_fnc_arg) {
	struct filterdata_sink_t flt_init_arg = {
		.sink_fnc = sink_fnc,
		.sink_fnc_arg = sink_fnc_arg,
	};
	return datafilter_new(&filterclass_sink, &flt_init_arg, NULL);
}

void datafilter_put(struct datafilter_t *filter, const void *data, unsigned int length) {
	filter->flt_class->flt_put(filter, data, length);
}

static void datafilter_free(struct datafilter_t *filter) {
	if (filter->flt_class->flt_free) {
		filter->flt_class->flt_free(filter->data);
	}
	free(filter->data);
	free(filter);
}

void datafilter_free_chain(struct datafilter_t *filter) {
	while (filter) {
		struct datafilter_t *next_filter = filter->next;
		datafilter_free(filter);
		filter = next_filter;
	}
}
