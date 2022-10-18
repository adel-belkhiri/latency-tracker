#ifndef _TP_BLOCK_LATENCY_H
#define _TP_BLOCK_LATENCY_H

/*
 * block_latency_tp.h
 *
 * Copyright (C) 2014 Julien Desfossez <jdesfossez@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <linux/tracepoint.h>
#include <linux/blkdev.h>
#include <linux/irq_work.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include "../latency_tracker.h"

enum wake_reason {
	OFFCPU_TRACKER_WAKE_DATA = 0,
	OFFCPU_TRACKER_WAIT = 1,
	OFFCPU_TRACKER_HUP = 2,
};

struct offcpu_tracker {
	u64 last_alert_ts;
	u64 ns_rate_limit;
	wait_queue_head_t read_wait;
	enum wake_reason reason;
	bool got_alert;
	int readers;
	struct irq_work w_irq;
	struct proc_dir_entry *proc_dentry;
};

static const struct proc_ops wakeup_tracker_fops;

int tracker_proc_release(struct inode *inode, struct file *filp);
int tracker_proc_open(struct inode *inode, struct file *filp);
ssize_t tracker_proc_read(struct file *filp, char __user *buf, size_t n,
	loff_t *offset);
unsigned int tracker_proc_poll(struct file *filp, poll_table *wait);
struct offcpu_tracker *offcpu_alloc_priv(void);
int offcpu_setup_priv(struct offcpu_tracker *wakeup_priv);
void offcpu_destroy_priv(struct offcpu_tracker *wakeup_priv);
void offcpu_handle_proc(struct offcpu_tracker *wakeup_priv,
		uint64_t end_ts);

static const
struct proc_ops wakeup_tracker_fops = {
	/*.owner = THIS_MODULE,*/
	.proc_open = tracker_proc_open,
	.proc_read = tracker_proc_read,
	.proc_release = tracker_proc_release,
	.proc_poll = tracker_proc_poll,
};

#endif /* _TP_BLOCK_LATENCY_H */
