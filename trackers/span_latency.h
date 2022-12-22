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
#define MAX_NUMBER_FILTER_SYSCALLS  256
#define LT_MAX_COOKIE_SIZE 64
#define LT_MAX_SPAN_ID_SIZE 16
#define LT_MAX_TRACE_ID_SIZE 32
#define SUBSTR_DELIM ":"


struct span_latency_tracker {
	int blacklisted_syscalls [MAX_NUMBER_FILTER_SYSCALLS];
	size_t nb_blacklisted_syscalls;

	struct proc_dir_entry* proc_dentry;
	struct dentry* debug_dentry;
};

struct string_key {
	char cookie[LT_MAX_COOKIE_SIZE];
	int cookie_size;
} __attribute__((__packed__));

struct span {
	struct string_key start_ts_abs;
	struct string_key span_id;
	struct string_key trace_id;
	/* To each span is connected 0..* syscalls */
	uint32_t nb_syscalls;
	struct list_head syscalls;
	struct list_head llist;
} __attribute__((__packed__));

struct process_key_t {
	pid_t pid;
} __attribute__((__packed__));

struct process_val_t {
	pid_t pid;
	pid_t tgid;
	char service_name[SERVICE_NAME_MAX_SIZE];
	struct process_val_t* parent;

	struct list_head spans;
	int take_stack_dump;
	struct rchan* rchann;
	struct hlist_node hlist;
	struct rcu_head rcu;
};

struct process_val_t* find_process(struct process_key_t* key, u32 hash);
void process_register(pid_t pid, pid_t tgid, struct span_latency_tracker* tracker_priv);
void process_unregister(pid_t pid);
void free_process_map(void);

int span_latency_tracker_setup_proc_priv(struct span_latency_tracker* tracker_priv);
int span_latency_tracker_setup_debug_priv(struct span_latency_tracker* tracker_priv,
	struct dentry* dir);
void span_latency_tracker_destroy_private(struct span_latency_tracker* tracker_priv);

int span_latency_tracker_proc_open(struct inode* inode, struct file* filp);
long span_latency_tracker_proc_ctl_ioctl(struct file* filp, unsigned int cmd, unsigned long arg);
int span_latency_tracker_proc_release(struct inode* inode, struct file* filp);

ssize_t span_latency_tracker_proc_filter_read(struct file *filp, char *user_buffer, size_t count, loff_t *offs);
ssize_t span_latency_tracker_proc_filter_write (struct file *filp, const char __user *user_buf,
											size_t count, loff_t *ppos);

static const struct proc_ops span_latency_tracker_ctl_fops = {
	.proc_open = span_latency_tracker_proc_open,
	.proc_ioctl = span_latency_tracker_proc_ctl_ioctl,
#ifdef CONFIG_COMPAT
	.proc_compat_ioctl = span_latency_tracker_proc_ctl_ioctl,
#endif
	.proc_release = span_latency_tracker_proc_release,
};

static const struct proc_ops span_latency_tracker_filter_fops = {
	.proc_open = span_latency_tracker_proc_open,
	.proc_read = span_latency_tracker_proc_filter_read,
	.proc_write = span_latency_tracker_proc_filter_write,
	.proc_release = span_latency_tracker_proc_release,
};

#endif /* _LATENCY_TRACKER_SPAN_LATENCY_H */