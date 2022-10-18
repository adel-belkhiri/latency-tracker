#ifndef _LATENCY_TRACKER_SPAN_LATENCY_RELAY_H
#define _LATENCY_TRACKER_SPAN_LATENCY_RELAY_H

#include <linux/relay.h>
#include <linux/debugfs.h>
#include "span_latency_abi.h"


struct syscall_desc{
	char name[SYSCALL_NAME_MAX_SIZE];
	uint16_t nr;
	uint64_t start;
	uint64_t end;
};

struct syscall{
	struct syscall_desc desc;
	struct list_head llist;
};

int userspace_tracker_setup_relay_channel(struct rchan **channel,
									unsigned int id, struct dentry* debug_dir);
void userspace_tracker_destroy_channel(struct rchan *channel);

#endif /* _LATENCY_TRACKER_SPAN_LATENCY_RELAY_H */