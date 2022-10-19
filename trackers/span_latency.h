#ifndef _LATENCY_TRACKER_SPAN_LATENCY_H
#define _LATENCY_TRACKER_SPAN_LATENCY_H

#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/relay.h>

#include "span_latency_relay.h"
#include "span_latency_abi.h"

#undef MAX_KEY_SIZE
#define MAX_KEY_SIZE sizeof(struct process_key_t)
#define DEBUGFS_DIR_PATH "channels"


struct span_latency_tracker {
	struct list_head spans;

	struct proc_dir_entry* proc_dentry;
	struct dentry *	debug_dentry;
};

struct process_key_t {
	pid_t tgid;
} __attribute__((__packed__));

struct process_val_t {
	pid_t tgid;
	char service_name[SERVICE_NAME_MAX_SIZE];
	int take_stack_dump;
	struct rchan *rchann;
	struct hlist_node hlist;
	struct rcu_head rcu;
};

struct process_val_t* find_process(struct process_key_t* key, u32 hash);
void process_register(pid_t tgid, const char* service_name, struct span_latency_tracker *tracker_priv);
void process_unregister(pid_t tgid);
void free_process_map(void);

int span_latency_tracker_setup_proc_priv(struct span_latency_tracker* tracker_priv);
int span_latency_tracker_setup_debug_priv(struct span_latency_tracker* tracker_priv,
	struct dentry* dir);
int span_latency_tracker_proc_open(struct inode *inode, struct file *filp);
long span_latency_tracker_proc_ioctl(
	struct file* filp, unsigned int cmd, unsigned long arg);
int span_latency_tracker_proc_release(struct inode *inode, struct file *filp);
void span_latency_tracker_destroy_private(struct span_latency_tracker *tracker_priv);

static const struct proc_ops span_latency_tracker_fops = {
	.proc_open = span_latency_tracker_proc_open,
	.proc_ioctl = span_latency_tracker_proc_ioctl,
#ifdef CONFIG_COMPAT
	.proc_compat_ioctl = span_latency_tracker_proc_ioctl,
#endif
	.proc_release = span_latency_tracker_proc_release,
};

#endif /* _LATENCY_TRACKER_SPAN_LATENCY_H */