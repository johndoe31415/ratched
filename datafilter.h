#ifndef __DATAFILTER_H__
#define __DATAFILTER_H__

#include <stdint.h>
#include <stdbool.h>

struct datafilter_t;

struct filterclass_t {
	const char *name;
	unsigned int datasize;
	bool (*flt_new)(void *data, void *init_attrs);
	void (*flt_flush)(struct datafilter_t *filter);
	void (*flt_put)(struct datafilter_t *filter, const uint8_t *data, unsigned int length);
	void (*flt_free)(void *data);
};

typedef void (*filter_sink_fnc_t)(void *arg, const uint8_t *data, unsigned int length);

struct datafilter_t {
	const struct filterclass_t *flt_class;
	struct datafilter_t *next;
	void *data;
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
struct datafilter_t *datafilter_new(const struct filterclass_t *flt_class, void *flt_init_args, struct datafilter_t *next);
struct datafilter_t *datafilter_new_sink(filter_sink_fnc_t sink_fnc, void *sink_fnc_arg);
void datafilter_put(struct datafilter_t *filter, const void *data, unsigned int length);
void datafilter_free_chain(struct datafilter_t *filter);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
