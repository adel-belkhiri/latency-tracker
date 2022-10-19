/*
 * span_latency.c
 *
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; only version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/jhash.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <asm/syscall.h>

#include "../latency_tracker.h"
#include "../tracker_debugfs.h"
#include "../wrapper/tracepoint.h"
#include "../wrapper/trace-clock.h"
#include "../wrapper/lt_probe.h"
#include "../wrapper/syscall_name.h"

#include "span_latency.h"
#include "span_latency_abi.h"
#include "span_latency_relay.h"

#include <trace/events/latency_tracker.h>

 /*
  * Limited to MAX_FILTER_STR_VAL (256) for ftrace compatibility.
  */
#define LT_MAX_COOKIE_SIZE 256
#define DELIM ":"

struct span_key {
	char cookie[LT_MAX_COOKIE_SIZE];
	int cookie_size;
} __attribute__((__packed__));

struct span {
	struct span_key key;
	/* To each span is connected [0..n[ syscalls */
	uint32_t nb_syscalls;
	struct list_head syscalls;
	struct list_head llist;
} __attribute__((__packed__));

#undef MAX_KEY_SIZE
#define MAX_KEY_SIZE sizeof(struct span_key)
#define TIMER_PERDIOD_MILLS    1*1000*1000 /*1 ms*/

struct event_data {
	pid_t tgid;
};

static struct latency_tracker* tracker;

static int cnt = 0;

static
void export_syscalls_relay(struct rchan* chan) {
	struct span_latency_tracker* tracker_priv;
	struct span* current_span;
	struct syscall* sys;
	struct list_head* ptr;
	char buff[128];
	char syscalls_data[8192];
	char header_data[64];
	char service_name[SERVICE_NAME_MAX_SIZE];
	char span_id[SPAN_ID_MAX_SIZE];
	char* sys_name;
	size_t header_offset, content_offset;
	uint32_t nb_copied_sys = 0;
	int ret;

	/* export the list of syscalls */
	tracker_priv = (struct span_latency_tracker*)latency_tracker_get_priv(tracker);
	current_span = list_first_entry_or_null(&tracker_priv->spans, struct span, llist);

	if (!current_span)
		return;

	/* write service name (28 c) */
	strcpy(service_name, "TEST_SERVICE");
	memcpy(header_data, service_name, sizeof(service_name));
	header_offset = sizeof(service_name);

	/* write the Span_id (32 c) */
	strncpy(span_id, current_span->key.cookie, sizeof(span_id) - 1);
	memcpy(header_data + header_offset, span_id, sizeof(span_id));
	header_offset += sizeof(span_id);

	content_offset = 0;

	list_for_each_prev(ptr, &current_span->syscalls) {
		sys = list_entry(ptr, struct syscall, llist);

		if ((content_offset + sizeof(sys->desc)) > sizeof(syscalls_data))
			goto finish;

		//FIXME: some syscalls don't have endtime?!
		if (sys->desc.start < sys->desc.end) {
			// copy syscall name
			ret = wrapper_get_syscall_name(sys->desc.nr, buff);
			WARN_ON_ONCE(ret);

			// eliminate __x64_sys_
			sys_name = strstr(buff, "_sys_");
			sys_name = (sys_name == NULL) ? buff : sys_name + 5;

			/* write syscall description */
			strncpy(sys->desc.name, sys_name, SYSCALL_NAME_MAX_SIZE);
			memcpy(syscalls_data + content_offset, &(sys->desc), sizeof(sys->desc));
			content_offset += sizeof(sys->desc);

			nb_copied_sys ++;
		}
	}

finish:

	printk("-- span_id: %s, nb_syscalls:%u, nb_copied_sys:%u",
		span_id, current_span->nb_syscalls, nb_copied_sys);

	/* write the number of syscalls (4 c) */
	memcpy(header_data + header_offset, &nb_copied_sys, sizeof(uint32_t));
	header_offset += sizeof(uint32_t);

	/* export the syscalls header */
	relay_write(chan, header_data, header_offset);

	/* export syscalls data */
	relay_write(chan, syscalls_data, content_offset);
	//relay_switch_subbuf(chan, ??? );
}

static
void span_lateny_cb(struct latency_tracker_event_ctx* ctx)
{

	struct event_data* data;
	struct span_key* key;
	struct process_key_t process_key;
	struct process_val_t* val;
	struct task_struct* task;
	int send_sig = 0;
	u32 hash;
	//struct latency_tracker_event *s;

	//uint64_t start_ts = latency_tracker_event_ctx_get_start_ts(ctx);
	//uint64_t end_ts = latency_tracker_event_ctx_get_end_ts(ctx);


	enum latency_tracker_cb_flag cb_flag =
		latency_tracker_event_ctx_get_cb_flag(ctx);

	if ((cb_flag != LATENCY_TRACKER_CB_TIMEOUT) && (cb_flag != LATENCY_TRACKER_CB_NORMAL))
		goto end_unlock;

	/* Get the event key and its private data */
	key = (struct span_key*) latency_tracker_event_ctx_get_key(ctx)->key;
	WARN_ON_ONCE(!key);

	data = (struct event_data*) latency_tracker_event_ctx_get_priv_data(ctx);
	WARN_ON_ONCE(!data);

	/* Search the 'task struct' related to the process that emitted the event */
	rcu_read_lock();
	process_key.tgid = data->tgid;
	hash = jhash(&process_key, sizeof(process_key), 0);
	val = find_process(&process_key, hash);
	rcu_read_unlock();

	if (!val)
		goto end_unlock;

	task = pid_task(find_vpid(val->tgid), PIDTYPE_PID);
	if (task)
		send_sig = 1;

	/* Span latency exceeded threshold, then export span's syscalls */
	if (cb_flag == LATENCY_TRACKER_CB_NORMAL)
		export_syscalls_relay(val->rchann);

	/* Send signal to let the application generate its call stack */
	if (send_sig)
		send_sig_info(SIGPROF, SEND_SIG_NOINFO, task);

	/*
	 * TODO: output an event in ftrace
	 * uint64_t delay = end_ts - start_ts;
	 * struct span_key *key = (struct span_key *)
	 * latency_tracker_event_ctx_get_key(ctx)->key;
	*/

	cnt++;
	latency_tracker_debugfs_wakeup_pipe(tracker);
	return;

end_unlock:
	rcu_read_unlock();
}

LT_PROBE_DEFINE(tracker_begin, char* tp_data, size_t len)
{
	struct span_key key;
	enum latency_tracker_event_in_ret ret;
	struct latency_tracker_event* event = NULL;
	struct event_data* data;
	u64 now;
	struct span* new_span;
	struct span_latency_tracker* tracker_priv;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!tp_data)
		return;

	/*
	 * Cookies must be strings, just a "echo > work_begin" is not accepted.
	 */
	if (len == 1 && (tp_data[0] == '\n' || tp_data[0] == '\0'))
		return;

	memset(&key, 0, sizeof(key));
	if (copy_from_user(&key.cookie, tp_data, len)) {
		printk("span latency tracker: error copying data from userspace...");
		return;
	}

	now = trace_clock_monotonic_wrapper();
	ret = _latency_tracker_event_in_get(tracker, &key, sizeof(key), 1, now,
		NULL, &event);

	if (ret != LATENCY_TRACKER_OK) {
		printk("span latency tracker: error inserting one event in the tracker (code = %u).", ret);
		return;
	}

	if (event != NULL) {
		data = (struct event_data*)
			latency_tracker_event_get_priv_data(event);
		WARN_ON(!data);
		if (data)
			data->tgid = current->tgid;
	}

	latency_tracker_unref_event(event);

	/*
	 * We need to save a copy of the span to keep track of active spans, and so that
	 * we can attach syscalls to them properly.
	 */
	tracker_priv = (struct span_latency_tracker*) latency_tracker_get_priv(tracker);
	new_span = kzalloc(sizeof(struct span), GFP_KERNEL);
	if (!new_span) {
		printk(KERN_ERR "span latency tracker: error allocating memory.");
		return; //return ERR_PTR(-ENOMEM);
	}
	new_span->key = key;
	INIT_LIST_HEAD(&new_span->syscalls);
	list_add(&new_span->llist, &tracker_priv->spans);
}

LT_PROBE_DEFINE(tracker_end, char* tp_data, size_t len)
{
	struct span_key key;
	struct span* span;
	struct list_head* ptr, * q;
	struct syscall* sys;
	struct span_latency_tracker* tracker_priv;
	int ret;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!tp_data)
		return;

	/*
	 * Cookies must be strings, just a "echo > work_begin" is not accepted.
	 */
	if (len == 1 && (tp_data[0] == '\n' || tp_data[0] == '\0'))
		return;

	memset(&key, 0, sizeof(key));
	if (copy_from_user(&key.cookie, tp_data, len)) {
		printk("Error copying from userspace...\n");
		return;
	}

	ret = latency_tracker_event_out(tracker, NULL, &key, sizeof(key), 0, 0);

	/* Delete the last span and all its syscalls, since the span is no longer active */
	tracker_priv = (struct span_latency_tracker*)latency_tracker_get_priv(tracker);
	span = list_first_entry_or_null(&tracker_priv->spans, struct span, llist);
	if (span) {
		/* Delete and free attached syscalls */
		list_for_each_safe(ptr, q, &span->syscalls) {
			sys = list_entry(ptr, struct syscall, llist);
			list_del(ptr);
			kfree(sys);
		}
		/* Delete the current span */
		list_del(&span->llist);
		kfree(span);
	}
}

LT_PROBE_DEFINE(syscall_enter, struct pt_regs* regs, long id)
{
	struct span_latency_tracker* tracker_priv;
	struct task_struct* task = current;
	struct process_key_t process_key;
	struct span* current_span;
	struct syscall* sys;
	u32 hash;
	u64 real_now;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	//TODO: Handle syscall filtering correctly
	if ((id == 0 /*read*/) || (id == 262 /*fstatat*/))
		return;

	real_now = ktime_get_real_ns();
	process_key.tgid = task->tgid;
	hash = jhash(&process_key, sizeof(process_key), 0);

	rcu_read_lock();
	if (!find_process(&process_key, hash)) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	/* current process is tracked, then add a syscall to the current active span */
	tracker_priv = (struct span_latency_tracker*)latency_tracker_get_priv(tracker);
	current_span = list_first_entry_or_null(&tracker_priv->spans, struct span, llist);
	if (current_span) {
		sys = kzalloc(sizeof(struct syscall), GFP_KERNEL);
		if (!sys) {
			printk(KERN_ERR "span latency tracker: error allocating memory.");
			return; /* ERR_PTR(-ENOMEM); */
		}

		sys->desc.nr = id;
		sys->desc.start = real_now;
		current_span->nb_syscalls++;
		list_add(&sys->llist, &current_span->syscalls);
	}
}

LT_PROBE_DEFINE(syscall_exit, struct pt_regs* regs, long ret)
{
	struct process_key_t key;
	struct span_latency_tracker* tracker_priv;
	struct task_struct* task = current;
	struct span* current_span;
	struct syscall* sys;
	u64 real_now;
	u32 hash;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	real_now = ktime_get_real_ns();
	key.tgid = task->tgid;
	hash = jhash(&key, sizeof(key), 0);

	rcu_read_lock();
	if (!find_process(&key, hash)) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	/* Fetch the syscall of the current span, then update its end timestamp */
	tracker_priv = (struct span_latency_tracker*) latency_tracker_get_priv(tracker);
	current_span = list_first_entry_or_null(&tracker_priv->spans, struct span, llist);
	if (current_span) {
		sys = list_first_entry_or_null(&current_span->syscalls, struct syscall, llist);
		if (sys)
			sys->desc.end = real_now;
	}
}


LT_PROBE_DEFINE(sched_process_exit, struct task_struct* p)
{
	/* If this is the main thread of a process, try to unregister the process.*/
	if (p->pid == p->tgid) {
		process_unregister(p->tgid);
	}
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
LT_PROBE_DEFINE(sched_switch, bool preempt, struct task_struct* prev,
	struct task_struct* next)
#else
LT_PROBE_DEFINE(sched_switch, struct task_struct* prev,
	struct task_struct* next)
#endif
{
	struct task_struct* task = next;
	struct process_key_t sched_key;
	struct latency_tracker_event* s;
	//char stacktxt[MAX_STACK_TXT];
	u64 now, delta, threshold;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!task)
		goto end;
	//	if (!take_kernel_stack)
	//		goto end;
	sched_key.tgid = task->pid;
	s = latency_tracker_get_event_by_key(tracker, &sched_key,
		sizeof(sched_key), NULL);
	if (!s)
		goto end;
	now = trace_clock_monotonic_wrapper();
	delta = now - latency_tracker_event_get_start_ts(s);
	threshold = latency_tracker_get_threshold(tracker);
	printk("-> sched_switch, pid:%d, delta:%llu, threshold:%llu\n",
		sched_key.tgid, delta, threshold
	);
	if (delta > ((threshold * 1000) / 2)) {
		/*get_stack_txt(stacktxt, task);
		trace_latency_tracker_syscall_stack(
				task->comm, task->pid, latency_tracker_event_get_start_ts(s),
				delta, 0, stacktxt);*/
		send_sig_info(SIGPROF, SEND_SIG_NOINFO, task);
	}
	latency_tracker_unref_event(s);

end:
	return;
}

static
struct span_latency_tracker* span_latency_tracker_alloc_priv(void)
{
	struct span_latency_tracker* tracker_priv;

	tracker_priv = kzalloc(sizeof(struct span_latency_tracker), GFP_KERNEL);
	if (!tracker_priv)
		return NULL;

	INIT_LIST_HEAD(&tracker_priv->spans);
	return tracker_priv;
}

void span_latency_tracker_destroy_private(struct span_latency_tracker* tracker_priv)
{
	struct span* sp;
	struct syscall* sys;
	struct list_head* ptr1, * q1, * ptr2, * q2;
	if (tracker_priv->proc_dentry) {
		remove_proc_entry(USERSPACE_TRACKER_PROC, NULL);
	}

	if (tracker_priv->debug_dentry) {
		debugfs_remove(tracker_priv->debug_dentry);
	}

	/* Delete attached spans and their syscalls */
	list_for_each_safe(ptr1, q1, &tracker_priv->spans) {
		sp = list_entry(ptr1, struct span, llist);
		list_for_each_safe(ptr2, q2, &sp->syscalls) {
			sys = list_entry(ptr2, struct syscall, llist);
			list_del(ptr2);
			kfree(sys);
		}
		list_del(ptr1);
		kfree(sp);
	}

	kfree(tracker_priv);
}

static
int __init span_latency_init(void)
{
	int ret;
	struct span_latency_tracker* tracker_priv;
	struct dentry* debug_dir;


	tracker_priv = span_latency_tracker_alloc_priv();
	if (!tracker_priv) {
		ret = -ENOMEM;
		goto end;
	}

	tracker = latency_tracker_create("spans");
	if (!tracker)
		goto error;

	latency_tracker_set_priv(tracker, tracker_priv);
	latency_tracker_set_callback(tracker, span_lateny_cb);
	latency_tracker_set_key_size(tracker, MAX_KEY_SIZE);
	latency_tracker_set_priv_data_size(tracker, sizeof(struct event_data));
	//latency_tracker_set_destroy_event_cb(tracker, destroy_event_cb);

	ret = latency_tracker_set_timer_period(tracker, TIMER_PERDIOD_MILLS);
	if (ret != 0)
		goto error;

	ret = latency_tracker_debugfs_setup_wakeup_pipe(tracker);
	if (ret != 0)
		goto error;

	debug_dir = latency_tracker_debugfs_add_subfolder(tracker, DEBUGFS_DIR_PATH);
	ret = span_latency_tracker_setup_debug_priv(tracker_priv, debug_dir);
	if (ret != 0)
		goto error;

	ret = span_latency_tracker_setup_proc_priv(tracker_priv);
	if (ret != 0)
		goto error;

	ret = lttng_wrapper_tracepoint_probe_register("latency_tracker_begin",
		probe_tracker_begin, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register("latency_tracker_end",
		probe_tracker_end, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register(
		"sched_process_exit", probe_sched_process_exit, NULL);
	WARN_ON(ret);
	ret = lttng_wrapper_tracepoint_probe_register(
		"sched_switch", probe_sched_switch, NULL);
	WARN_ON(ret);

	ret = lttng_wrapper_tracepoint_probe_register(
		"sys_enter", probe_syscall_enter, NULL);
	WARN_ON(ret);
	ret = lttng_wrapper_tracepoint_probe_register(
		"sys_exit", probe_syscall_exit, NULL);
	WARN_ON(ret);

	goto end;

error:
	ret = -1;
end:
	return ret;
}
module_init(span_latency_init);

static
void __exit span_latency_exit(void)
{
	uint64_t skipped;
	struct span_latency_tracker* tracker_priv;

	lttng_wrapper_tracepoint_probe_unregister("latency_tracker_begin",
		probe_tracker_begin, NULL);
	lttng_wrapper_tracepoint_probe_unregister("latency_tracker_end",
		probe_tracker_end, NULL);
	lttng_wrapper_tracepoint_probe_unregister("sched_process_exit",
		probe_sched_process_exit, NULL);
	lttng_wrapper_tracepoint_probe_unregister("sched_switch",
		probe_sched_switch, NULL);
	lttng_wrapper_tracepoint_probe_unregister("sys_enter",
		probe_syscall_enter, NULL);
	lttng_wrapper_tracepoint_probe_unregister("sys_exit",
		probe_syscall_exit, NULL);

	tracepoint_synchronize_unregister();
	free_process_map();

	skipped = latency_tracker_skipped_count(tracker);
	tracker_priv = (struct span_latency_tracker*) latency_tracker_get_priv(tracker);
	span_latency_tracker_destroy_private(tracker_priv);
	latency_tracker_destroy(tracker);
	printk("Span latency tracker: missed events : %llu\n", skipped);
	printk("Span latency tracker: total alerts : %d\n", cnt);
}
module_exit(span_latency_exit);

MODULE_AUTHOR("Adel Belkhiri <adel.belkhiri@polymtl.ca>");
MODULE_LICENSE("GPL and additional rights");
MODULE_VERSION("1.0");
