#ifndef _LATENCY_TRACKER_SPAN_LATENCY_RELAY_H
#define _LATENCY_TRACKER_SPAN_LATENCY_RELAY_H

#include <linux/relay.h>
#include <linux/debugfs.h>
#include "span_latency_abi.h"


struct syscall_desc {
	char name[SYSCALL_NAME_MAX_SIZE];
	uint64_t start_system;
	uint64_t start_steady;
	uint64_t end_steady;
};

struct syscall {
	uint16_t id;
	struct syscall_desc desc;
	struct list_head llist;
};

int span_latency_tracker_setup_relay_channel(struct rchan** channel,
	unsigned int id, struct dentry* debug_dir);
void span_latency_tracker_destroy_channel(struct rchan* channel);

#endif /* _LATENCY_TRACKER_SPAN_LATENCY_RELAY_H */