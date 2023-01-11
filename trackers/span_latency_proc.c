#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/debugfs.h>

#include "span_latency.h"
#include "span_latency_abi.h"
#include "span_latency_relay.h"


static DEFINE_HASHTABLE(process_map, 3);


static void free_process_val_rcu(struct rcu_head* rcu)
{
	kfree(container_of(rcu, struct process_val_t, rcu));
}

struct process_val_t* find_process(struct process_key_t* key, u32 hash)
{
	struct process_val_t* val;

	hash_for_each_possible_rcu(process_map, val, hlist, hash) {
		if (key->pid == val->pid) {
			return val;
		}
	}
	return NULL;
}

void free_process_map()
{
	struct span* sp;
	struct syscall* sys;
	struct list_head* ptr1, * q1, * ptr2, * q2;
	struct process_val_t* process_val;
	int bkt;

	rcu_read_lock();
	hash_for_each_rcu(process_map, bkt, process_val, hlist) {
		/* Delete attached spans and their syscalls */
		list_for_each_safe(ptr1, q1, &process_val->spans) {
			sp = list_entry(ptr1, struct span, llist);
			list_for_each_safe(ptr2, q2, &sp->syscalls) {
				sys = list_entry(ptr2, struct syscall, llist);
				list_del(ptr2);
				kfree(sys);
			}
			list_del(ptr1);
			kfree(sp);
		}

		/* Delete the relay channel */
		if(process_val->pid == process_val->tgid)
			span_latency_tracker_destroy_channel(process_val->rchann);

		hash_del_rcu(&process_val->hlist);
		call_rcu(&process_val->rcu, free_process_val_rcu);
	}
	rcu_read_unlock();
}

void process_register(pid_t pid, pid_t tgid, struct span_latency_tracker* tracker_priv)
{
	u32 hash, hash_parent;
	struct process_key_t key, key_parent;
	struct process_val_t* val, *parent_val;
	int ret;

	key.pid = pid;
	hash = jhash(&key, sizeof(key), 0);

	/* Make sure the process is not already registered */
	rcu_read_lock();
	val = find_process(&key, hash);
	if (val) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	/* Create the new data structure */
	val = kzalloc(sizeof(struct process_val_t), GFP_KERNEL);
	val->pid = pid;
	val->tgid = tgid;
	INIT_LIST_HEAD(&val->spans);

	/* Setup just one relay file for all the processes whose thread group id = tgid */
	if (pid == tgid) {
		val->parent = NULL;
		ret = span_latency_tracker_setup_relay_channel(&(val->rchann), tgid, tracker_priv->debug_dentry);
		if (ret)
			printk(KERN_WARNING "span latency tracker: Error setting up a relay channel for process %d",
				tgid);
	}
	else {
		/* Link the current process to the parent process data structure */
		key_parent.pid = tgid;
		hash_parent = jhash(&key_parent, sizeof(key_parent), 0);

		rcu_read_lock();
		parent_val = find_process(&key_parent, hash_parent);
		if (unlikely(!parent_val)) {
			rcu_read_unlock();
			kfree (val);
			return;
		}
		rcu_read_unlock();
		val->parent = parent_val;
	}

	hash_add_rcu(process_map, &val->hlist, hash);
	printk("span latency tracker: registered a process (pid: %d)\n", pid);
}

void process_unregister(pid_t pid)
{
	struct process_key_t key;
	struct process_val_t* val;
	u32 hash;
	pid_t child_pid;
	struct process_val_t* child_val;
	int bkt;

	key.pid = pid;
	hash = jhash(&key, sizeof(key), 0);
	rcu_read_lock();
	val = find_process(&key, hash);
	if (val) {
		/* if it is the main thread, then unregister all its children and release the relay channel */
		//TODO: this generates a rcu warning
		if (pid == val->tgid) {
			//hash_for_each_rcu(process_map, bkt, child_val, hlist) {
			//	if (pid == child_val->tgid) {
			//		child_pid = child_val->pid;

			//		hash_del_rcu(&child_val->hlist);
			//		call_rcu(&child_val->rcu, free_process_val_rcu);
			//		printk("span latency tracker: unregistered a process (pid: %d)\n", child_pid);
			//	}
			//}

			span_latency_tracker_destroy_channel(val->rchann);
		}

		hash_del_rcu(&val->hlist);
		call_rcu(&val->rcu, free_process_val_rcu);
		printk("span latency tracker: unregistered a process (pid: %d)\n", pid);
	}
	rcu_read_unlock();

}

int span_latency_tracker_setup_proc_priv(struct span_latency_tracker* tracker_priv)
{
	struct proc_dir_entry *proc_ioctl, *proc_parent;

	proc_parent = proc_mkdir(SPAN_LATENCY_TRACKER_PROC, NULL);
	if (!proc_parent)
		goto fail_alloc;

	proc_ioctl = proc_create_data(SPAN_LATENCY_TRACKER_PROC_CTL,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
		proc_parent, &span_latency_tracker_ctl_fops, tracker_priv);

	if (!proc_ioctl)
		goto fail_alloc;

	proc_ioctl = proc_create_data(SPAN_LATENCY_TRACKER_PROC_FILTER,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
		proc_parent, &span_latency_tracker_filter_fops, tracker_priv);

	if (!proc_ioctl)
		goto fail_alloc;

	tracker_priv->proc_dentry = proc_parent;
	return 0;

fail_alloc:
	printk(KERN_ERR "span latency tracker: error creating tracker control file.");
	return -ENOMEM;
}

int span_latency_tracker_setup_debug_priv(struct span_latency_tracker* tracker_priv,
	struct dentry* dir)
{
	if (dir == NULL) {
		printk(KERN_ERR "span latency tracker: error creating tracker debugfs file.");
		return -ENOMEM;
	}
	tracker_priv->debug_dentry = dir;
	return 0;
}

int span_latency_tracker_proc_open(struct inode* inode, struct file* filp)
{
	struct span_latency_tracker* tracker_priv = PDE_DATA(inode);
	int ret;

	filp->private_data = tracker_priv;
	ret = try_module_get(THIS_MODULE);
	if (!ret)
		return -1;

	return 0;
}

long span_latency_tracker_proc_ctl_ioctl(
	struct file* filp, unsigned int cmd, unsigned long arg)
{
	struct span_latency_tracker* tracker_priv = filp->private_data;
	struct span_latency_tracker_module_msg msg;
	int ret = 0;
	void __user* umsg = (void*) arg;

	if (cmd != SPAN_LATENCY_TRACKER_IOCTL)
		return -ENOIOCTLCMD;

	if (copy_from_user(&msg, umsg, sizeof(msg)))
		return -EFAULT;

	switch (msg.cmd) {
	case SPAN_LATENCY_TRACKER_MODULE_REGISTER:
		process_register(current->pid, current->tgid, /*msg.service_name,*/ tracker_priv);
		break;
	case SPAN_LATENCY_TRACKER_MODULE_UNREGISTER:
		process_unregister(current->pid);
		break;
	default:
		ret = -ENOTSUPP;
		break;
	}

	return ret;
}

int span_latency_tracker_proc_release(struct inode* inode, struct file* filp)
{
	module_put(THIS_MODULE);
	return 0;
}

ssize_t span_latency_tracker_proc_filter_write (struct file *filp, const char __user *user_buf,
											size_t count, loff_t *ppos)
{

	char kern_buff[1024];
	size_t nb_bytes_to_copy, nb_bytes_not_copied, nb_bytes_copied, i, p = 0;
	char* syscalls_string_ptr, *token;
	int duplicate = 0;
	unsigned int nr;

	struct span_latency_tracker* tracker_priv = filp->private_data;
	tracker_priv->nb_blacklisted_syscalls = 0;

	nb_bytes_to_copy = min_t(size_t, count, sizeof(kern_buff) - 1 );
	nb_bytes_not_copied = copy_from_user(kern_buff, user_buf, nb_bytes_to_copy);

	nb_bytes_copied = nb_bytes_to_copy - nb_bytes_not_copied;
	kern_buff[nb_bytes_copied] = '\0';

	syscalls_string_ptr = kern_buff;
	while ((token = strsep(&syscalls_string_ptr, " ")) && (syscalls_string_ptr < kern_buff + nb_bytes_copied)) {
		if (kstrtouint(token, 10, &nr))
			continue;

		for (i = 0; i < tracker_priv->nb_blacklisted_syscalls; i++) {
			if (nr > tracker_priv->blacklisted_syscalls[i]) {
				p = i + 1;
			}
			else {
				if (nr < tracker_priv->blacklisted_syscalls[i]) {
					p = i;
				}
				else {
					duplicate = 1;
				}
				break;
			}
		}

		if(!duplicate) {
			/* move all data to the right side */
			for (i = tracker_priv->nb_blacklisted_syscalls; i > p; i--)
				tracker_priv->blacklisted_syscalls[i] = tracker_priv->blacklisted_syscalls[i - 1];

			/* insert the syscall number at the right position */
			tracker_priv->blacklisted_syscalls[p] = nr;
			tracker_priv->nb_blacklisted_syscalls += 1;
		}
	}

	return nb_bytes_copied;
}

ssize_t span_latency_tracker_proc_filter_read(struct file *filp, char *user_buffer, size_t count, loff_t *offs) {
	//int to_copy, not_copied, delta;
	int i, offset = 0;
	struct span_latency_tracker* tracker_priv = filp->private_data;
	char buff[200];

	if (*offs > 0) {
		/* we have finished to read, return 0 */
		return 0;
	}

	printk("number of blacklisted syscalls: %lu", tracker_priv->nb_blacklisted_syscalls);


	for(i = 0; i < tracker_priv->nb_blacklisted_syscalls; i++) {
		offset += snprintf(buff + offset, 200, "%u ", tracker_priv->blacklisted_syscalls[i]);
	}
	*(buff + offset) = '\0';
	printk("blacklisted syscalls: %s", buff);

	/* Get amount of data to copy */
	//to_copy = min(count, sizeof(kern_buf));

	/* Copy data to user */
	//not_copied = copy_to_user(user_buffer, kern_buf, to_copy);

	/* Calculate data */
	//delta = to_copy - not_copied;

	/* Set the offset to indicate that data was read completely */
	//*offs = delta;

	/* update stats */
	//priv_data = filp->private_data;
	//priv_data->nb_read++;

	return 0;//delta;
}




