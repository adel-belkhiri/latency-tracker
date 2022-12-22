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
#include <linux/string.h>

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

#undef MAX_KEY_SIZE
#define MAX_KEY_SIZE sizeof(struct string_key)
#define TIMER_PERDIOD_MILLS    1*1000*1000 /*1 ms*/

struct event_data {
	pid_t pid;
};

static struct latency_tracker* tracker;

static int cnt = 0;

inline
bool is_syscall_blacklisted(int* array, int syscall_nr, size_t size) {
    size_t mid;
	int first, last;


	if(size == 0)
		return false;

	first = 0;
    last = size - 1;
    while (first <= last) {
        mid = (first + last) / 2;

		if (array[mid] == syscall_nr)
			return true;

        if (array[mid] < syscall_nr ) {
			first = mid + 1;
        } else {
			last = mid - 1;
        }
    }
    return false;
}

/**
 * @brief This function exports the syscalls of a specific span to a relay file.
 *
 * @param thread
 *
 * NOTE: there is room for improvement in this function. For instance:
 * 	1- use an array of syscall_desc instead of a cstring to write syscalls.
 * 	2- make exporting syscalls not limited to a specific cap.
 */
static
void export_syscalls_relay(struct process_val_t* thread, uint64_t span_start_ts, uint64_t span_end_ts) {
	struct span* current_span;
	struct syscall* sys;
	struct list_head* ptr;
	char buff[128];
	char syscalls_data[8192];
	char header_data[64];
	char service_name[SERVICE_NAME_MAX_SIZE + 1];
	char* sys_name;
	size_t header_offset = 0, content_offset = 0;
	uint32_t nb_copied_syscalls = 0;
	struct rchan* chan;
	struct rchan_buf *chan_buf;
	int ret;
	uint64_t start_ts_abs;

	current_span = list_first_entry_or_null(&thread->spans, struct span, llist);
	if (!current_span)
		return;

	/* convert the received span "real" start timestamp */
	ret = kstrtoll(current_span->start_ts_abs.cookie, 16, &start_ts_abs);
	if(ret) {
		printk("Error converting the received span start timestamp...(ret = %d)\n", ret);
		return;
	}

	/* browse syscalls attached to current span */
	list_for_each_prev(ptr, &current_span->syscalls) {
		sys = list_entry(ptr, struct syscall, llist);

		if ((content_offset + sizeof(sys->desc)) > sizeof(syscalls_data))
			goto finish;

		// copy syscall name
		ret = wrapper_get_syscall_name(sys->id, buff);
		WARN_ON_ONCE(ret);

		// eliminate __x64_sys_
		sys_name = strstr(buff, "_sys_");
		sys_name = (sys_name == NULL) ? buff : sys_name + 5;

		/* write syscall description */
		memset(sys->desc.name, 0 , SYSCALL_NAME_MAX_SIZE);
		strncpy(sys->desc.name, sys_name, SYSCALL_NAME_MAX_SIZE - 1);
		//sys->desc.start_system = start_ts_abs + (sys->desc.start_steady - span_start_ts);

		memcpy(syscalls_data + content_offset, &(sys->desc), sizeof(struct syscall_desc));
		content_offset += sizeof(sys->desc);

		nb_copied_syscalls++;
	}

finish:
	if (nb_copied_syscalls == 0)
		return;

	/* Fetch the relay file */
	if (thread->pid == thread->tgid)
		chan = thread->rchann;
	else
		chan = thread->parent->rchann;

	/* write the number of syscalls (4 c) */
	memcpy(header_data + header_offset, &nb_copied_syscalls, sizeof(uint32_t));
	header_offset += sizeof(uint32_t);

	/* write service name (12 c) */
	strcpy(service_name, "TEST_SERV");
	memcpy(header_data + header_offset, service_name, SERVICE_NAME_MAX_SIZE);
	header_offset += SERVICE_NAME_MAX_SIZE;

	/* write the Span_id (16 c) */
	memcpy(header_data + header_offset, current_span->span_id.cookie, SPAN_ID_MAX_SIZE);
	header_offset += SPAN_ID_MAX_SIZE;

	/* write the trace_id (32 c) */
	memcpy(header_data + header_offset, current_span->trace_id.cookie, TRACE_ID_MAX_SIZE);
	header_offset += TRACE_ID_MAX_SIZE;

	/* export the syscalls header */
	relay_write(chan, header_data, header_offset);

	/* export syscalls data */
	relay_write(chan, syscalls_data, content_offset);

	/* switch to a new subbuff to activate readers */
	chan_buf = *per_cpu_ptr(chan->buf, 0);
	relay_switch_subbuf(chan_buf, 0);
}

static
void span_lateny_cb(struct latency_tracker_event_ctx* ctx)
{

	struct event_data* data;
	struct string_key* key;
	struct process_key_t process_key;
	struct process_val_t* val;
	struct task_struct* task;
	int send_sig = 0;
	u32 hash;
	uint64_t start_ts, end_ts;
	//struct latency_tracker_event *s;

	enum latency_tracker_cb_flag cb_flag =
		latency_tracker_event_ctx_get_cb_flag(ctx);

	if ((cb_flag != LATENCY_TRACKER_CB_TIMEOUT) && (cb_flag != LATENCY_TRACKER_CB_NORMAL))
		return;

	/* Get the event key and its private data */
	key = (struct string_key*) latency_tracker_event_ctx_get_key(ctx)->key;
	WARN_ON_ONCE(!key);

	data = (struct event_data*) latency_tracker_event_ctx_get_priv_data(ctx);
	WARN_ON_ONCE(!data);

	/* Search the 'task struct' related to the process that emitted the event */
	process_key.pid = data->pid;
	hash = jhash(&process_key, sizeof(process_key), 0);
	rcu_read_lock();
	val = find_process(&process_key, hash);
	if (!val) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	/* We need the task structure to send a signal to the main monitoring thread*/
	task = pid_task(find_vpid(val->tgid), PIDTYPE_PID);
	if (task)
		send_sig = 1;

	/* Send signal to let the application generate its call stack */
	if (send_sig)
		send_sig_info(SIGPROF, SEND_SIG_NOINFO, task);

	/* Span latency exceeded threshold, then export span's syscalls */
	start_ts = latency_tracker_event_ctx_get_start_ts(ctx);
	end_ts = latency_tracker_event_ctx_get_end_ts(ctx);
	if (cb_flag == LATENCY_TRACKER_CB_NORMAL)
		export_syscalls_relay(val, start_ts, end_ts);

	/*
	 * TODO: output an event in ftrace
	 * uint64_t delay = end_ts - start_ts;
	 * struct string_key *key = (struct string_key *)
	 * latency_tracker_event_ctx_get_key(ctx)->key;
	*/

	cnt++;
	latency_tracker_debugfs_wakeup_pipe(tracker);
}

LT_PROBE_DEFINE(tracker_begin, char* tp_data, size_t len)
{
	struct string_key span_id, trace_id, start_ts_abs;
	enum latency_tracker_event_in_ret ret;
	struct latency_tracker_event* event = NULL;
	struct event_data* data;
	u64 now;
	struct span* new_span, *old_span;
	struct process_key_t thr_key;
	struct process_val_t* thr_val;
	struct syscall * orphan_syscall;
	char user_buf[256];
	char *token, *end;
	u32 hash;
	size_t max_length;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!tp_data)
		return;

	 /* Cookies must be strings, just a "echo > work_begin" is not accepted */
	if (len == 1 && (tp_data[0] == '\n' || tp_data[0] == '\0'))
		return;

	now = trace_clock_monotonic_wrapper();

	/* Only tracked threads have the right to emit begin/end events */
	thr_key.pid = current->pid;
	hash = jhash(&thr_key, sizeof(thr_key), 0);
	rcu_read_lock();
	thr_val = find_process(&thr_key, hash);
	if (!thr_val) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	max_length = min(len, sizeof(user_buf));
	if (copy_from_user(user_buf, tp_data, max_length)) {
		printk("span latency tracker: error copying data from userspace...\n");
		return;
	}
	user_buf[max_length - 1] = '\0';

	memset(&span_id, 0, sizeof(span_id));
	memset(&trace_id, 0, sizeof(trace_id));
	memset(&start_ts_abs, 0, sizeof(start_ts_abs));

	/* Check if start_ts is provided. Input format: start_ts:span_id:trace_id
	TODO: Must the input be in a fixed format or not ?! */
	end = user_buf;
	if ((token = strsep(&end, SUBSTR_DELIM)) != NULL) {
		memcpy(start_ts_abs.cookie, token, SPAN_ID_MAX_SIZE);

		if ((token = strsep(&end, SUBSTR_DELIM)) != NULL) {
			memcpy(span_id.cookie, token, SPAN_ID_MAX_SIZE);
			memcpy(trace_id.cookie, end, TRACE_ID_MAX_SIZE);
		}
	}

	ret = _latency_tracker_event_in_get(tracker, &span_id, sizeof(span_id), 1, now, NULL, &event);
	if (ret != LATENCY_TRACKER_OK) {
		printk("span latency tracker: error inserting one event in the tracker (code = %u).", ret);
		return;
	}

	if (event != NULL) {
		data = (struct event_data*)
			latency_tracker_event_get_priv_data(event);
		WARN_ON(!data);
		if (data)
			data->pid = thr_val->pid;
	}

	latency_tracker_unref_event(event);

	/* Delete the orphan write syscall that caused this event to trigger */
	old_span = list_first_entry_or_null(&thr_val->spans, struct span, llist);
	if (old_span) {
		orphan_syscall = list_first_entry_or_null(&old_span->syscalls, struct syscall, llist);
		if(orphan_syscall) {
			list_del(&orphan_syscall->llist);
			kfree(orphan_syscall);

			old_span->nb_syscalls -= 1;
		}
	}

	/*
	 * We need to save a copy of the span to keep track of active spans, and so that
	 * we can attach syscalls to them properly.
	 */
	new_span = kzalloc(sizeof(struct span), GFP_KERNEL);
	if (!new_span) {
		printk(KERN_ERR "span latency tracker: error allocating memory.\n");
		return; //return ERR_PTR(-ENOMEM);
	}
	new_span->start_ts_abs = start_ts_abs;
	new_span->span_id = span_id;
	new_span->trace_id = trace_id;
	INIT_LIST_HEAD(&new_span->syscalls);

	list_add(&new_span->llist, &thr_val->spans);
}

LT_PROBE_DEFINE(tracker_end, char* tp_data, size_t len)
{
	struct string_key key;
	struct span* span;
	struct list_head* ptr, * q;
	struct syscall* sys;
	struct process_key_t thr_key;
	struct process_val_t* thr_val;
	u32 hash;
	u64 now;
	int ret;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	if (!tp_data)
		return;

	 /* Cookies must be strings, just a "echo > work_begin" is not accepted. */
	if (len == 1 && (tp_data[0] == '\n' || tp_data[0] == '\0'))
		return;

	now = trace_clock_monotonic_wrapper();

	/* Only tracked threads have the right to emit begin/end events */
	thr_key.pid = current->pid;
	hash = jhash(&thr_key, sizeof(thr_key), 0);
	rcu_read_lock();
	thr_val = find_process(&thr_key, hash);
	if (!thr_val) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	memset(&key, 0, sizeof(key));
	if (copy_from_user(&key.cookie, tp_data, len)) {
		printk("Error copying from userspace...\n");
		return;
	}
	/* remove the '\n' character */
	key.cookie[strlen(key.cookie) - 1] = '\0';

	span = list_first_entry_or_null(&thr_val->spans, struct span, llist);
	if (span) {
		/* delete the orphan write syscall */
		sys = list_first_entry_or_null(&span->syscalls, struct syscall, llist);
		if (sys) {
			list_del(&sys->llist);
			kfree(sys);

			span->nb_syscalls -= 1;
		}

		/* Indicate the end of the span for latency tracker */
		ret = latency_tracker_event_out(tracker, NULL, &key, sizeof(key), 0, now);

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
	struct span* current_span;
	struct syscall* sys;
	struct process_key_t thr_key;
	struct process_val_t* thr_val;
	u32 hash;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	/* Is this thread tracked? */
	thr_key.pid = current->pid;
	hash = jhash(&thr_key, sizeof(thr_key), 0);
	rcu_read_lock();
	thr_val = find_process(&thr_key, hash);
	if (!thr_val) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	/* check if this syscall is filtered by the user */
	tracker_priv = (struct span_latency_tracker*) latency_tracker_get_priv(tracker);
	if(is_syscall_blacklisted(tracker_priv->blacklisted_syscalls, id, tracker_priv->nb_blacklisted_syscalls))
		return;

	/* If not, then add this syscall to the active span started by this thread */
	current_span = list_first_entry_or_null(&thr_val->spans, struct span, llist);
	if (current_span) {
		WARN_ON (current->pid != thr_val->pid);

		sys = kzalloc(sizeof(struct syscall), GFP_KERNEL);
		if (!sys) {
			printk(KERN_ERR "span latency tracker: error allocating memory.\n");
			return;
		}
		/* Add the new syscall */
		sys->id = id;
		sys->desc.start_system = ktime_get_real_ns(); //ktime_get_clocktai_ns();// //system ts
		sys->desc.start_steady = trace_clock_monotonic_wrapper(); //steady ts
		list_add(&sys->llist, &current_span->syscalls);

		current_span->nb_syscalls++;
	}
}

LT_PROBE_DEFINE(syscall_exit, struct pt_regs* regs, long ret)
{
	struct process_key_t thr_key;
	struct process_val_t* thr_val;
	struct task_struct* task = current;
	struct span* current_span;
	struct syscall* current_syscall;
	u32 hash;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	/* Does this syscall belong to a tracked thread? */
	thr_key.pid = task->pid;
	hash = jhash(&thr_key, sizeof(thr_key), 0);
	rcu_read_lock();
	thr_val = find_process(&thr_key, hash);
	if (!thr_val) {
		rcu_read_unlock();
		return; //BUG:
	}
	rcu_read_unlock();

	/* Fetch the syscall of the current span, then update its end timestamp */
	current_span = list_first_entry_or_null(&thr_val->spans, struct span, llist);
	if (current_span) {
		current_syscall = list_first_entry_or_null(&current_span->syscalls, struct syscall, llist);
		if (current_syscall && (current_syscall->desc.end_steady == 0)) {
			current_syscall->desc.end_steady = trace_clock_monotonic_wrapper();
		}
	}
}

LT_PROBE_DEFINE(task_newtask, struct task_struct *p, unsigned long clone_flags)
{
	struct span_latency_tracker* tracker_priv;
	u32 hash;
	struct process_key_t key;

	if (!latency_tracker_get_tracking_on(tracker))
		return;

	/* We are only interested in child threads */
	if (clone_flags & CLONE_THREAD) {
		key.pid = p->tgid;
		hash = jhash(&key, sizeof(key), 0);

		/* if the parent thread is not registered, no need to register the child too */
		rcu_read_lock();
		if (!find_process(&key, hash)) {
			rcu_read_unlock();
			return;
		}
		rcu_read_unlock();

		tracker_priv = (struct span_latency_tracker*) latency_tracker_get_priv(tracker);
		process_register(p->pid, p->tgid, tracker_priv);
    }

}

LT_PROBE_DEFINE(sched_process_exit, struct task_struct* p)
{
	/* Try to unregister the process if it was registred.*/
	process_unregister(p->pid);
}

/* #if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
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
	sched_key.pid = task->pid;
	s = latency_tracker_get_event_by_key(tracker, &sched_key,
		sizeof(sched_key), NULL);
	if (!s)
		goto end;
	now = trace_clock_monotonic_wrapper();
	delta = now - latency_tracker_event_get_start_ts(s);
	threshold = latency_tracker_get_threshold(tracker);
	printk("-> sched_switch, pid:%d, delta:%llu, threshold:%llu\n",
		sched_key.tgid, delta, threshold);

	if (delta > ((threshold * 1000) / 2)) {
		//get_stack_txt(stacktxt, task);
		//trace_latency_tracker_syscall_stack(
		//		task->comm, task->pid, latency_tracker_event_get_start_ts(s),
		//		delta, 0, stacktxt);
		send_sig_info(SIGPROF, SEND_SIG_NOINFO, task);
	}
	latency_tracker_unref_event(s);

end:
	return;
} */

static
struct span_latency_tracker* span_latency_tracker_alloc_priv(void)
{
	struct span_latency_tracker* tracker_priv;

	tracker_priv = kzalloc(sizeof(struct span_latency_tracker), GFP_KERNEL);
	if (!tracker_priv)
		return NULL;

	return tracker_priv;
}

void span_latency_tracker_destroy_private(struct span_latency_tracker* tracker_priv)
{

	if (tracker_priv->proc_dentry) {
		proc_remove(tracker_priv->proc_dentry);
	}

	if (tracker_priv->debug_dentry) {
		debugfs_remove(tracker_priv->debug_dentry);
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
		"task_newtask", probe_task_newtask, NULL);
	WARN_ON(ret);
	ret = lttng_wrapper_tracepoint_probe_register(
		"sched_process_exit", probe_sched_process_exit, NULL);
	WARN_ON(ret);
	//ret = lttng_wrapper_tracepoint_probe_register(
	//	"sched_switch", probe_sched_switch, NULL);
	//WARN_ON(ret);

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
	lttng_wrapper_tracepoint_probe_unregister("task_newtask",
		probe_task_newtask, NULL);
	//lttng_wrapper_tracepoint_probe_unregister("sched_switch",
	//	probe_sched_switch, NULL);
	lttng_wrapper_tracepoint_probe_unregister("sys_enter",
		probe_syscall_enter, NULL);
	lttng_wrapper_tracepoint_probe_unregister("sys_exit",
		probe_syscall_exit, NULL);

	tracepoint_synchronize_unregister();
	free_process_map();

	skipped = latency_tracker_skipped_count(tracker);
	tracker_priv = (struct span_latency_tracker*)latency_tracker_get_priv(tracker);
	span_latency_tracker_destroy_private(tracker_priv);
	latency_tracker_destroy(tracker);
	printk("Span latency tracker: missed events : %llu\n", skipped);
	printk("Span latency tracker: total alerts : %d\n", cnt);
}
module_exit(span_latency_exit);

MODULE_AUTHOR("Adel Belkhiri <adel.belkhiri@polymtl.ca>");
MODULE_LICENSE("GPL and additional rights");
MODULE_VERSION("1.0");
