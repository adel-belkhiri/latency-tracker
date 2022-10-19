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
		if (key->tgid == val->tgid) {
			return val;
		}
	}
	return NULL;
}

void free_process_map()
{
	struct process_val_t* process_val;
	int bkt;

	rcu_read_lock();
	hash_for_each_rcu(process_map, bkt, process_val, hlist) {
		/* destroy the relay channel */
		span_latency_tracker_destroy_channel(process_val->rchann);

		hash_del_rcu(&process_val->hlist);
		call_rcu(&process_val->rcu, free_process_val_rcu);
	}
	rcu_read_unlock();
}

void process_register(pid_t tgid, const char* service_name, struct span_latency_tracker* tracker_priv)
{
	u32 hash;
	struct process_key_t key;
	struct process_val_t* val;
	int ret;

	key.tgid = tgid;
	hash = jhash(&key, sizeof(key), 0);

	rcu_read_lock();
	val = find_process(&key, hash);
	if (val) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	val = kzalloc(sizeof(struct process_val_t), GFP_KERNEL);
	strncpy(val->service_name, service_name, SERVICE_NAME_MAX_SIZE);
	val->tgid = tgid;

	ret = span_latency_tracker_setup_relay_channel(&(val->rchann), tgid, tracker_priv->debug_dentry);
	if (ret)
		printk(KERN_WARNING "span latency tracker: Error setting up a relay channel for process %d",
			tgid);

	hash_add_rcu(process_map, &val->hlist, hash);
	printk("span latency tracker: registered a process (pid: %d, service name: %s)",
		tgid, service_name);
}

void process_unregister(pid_t tgid)
{
	struct process_key_t key;
	struct process_val_t* val;
	u32 hash;

	key.tgid = tgid;
	hash = jhash(&key, sizeof(key), 0);

	rcu_read_lock();
	val = find_process(&key, hash);
	if (val) {
		span_latency_tracker_destroy_channel(val->rchann);

		hash_del_rcu(&val->hlist);
		call_rcu(&val->rcu, free_process_val_rcu);
		printk("userspace tracker: unregistered a process (pid: %d)\n", tgid);
	}
	rcu_read_unlock();
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

long span_latency_tracker_proc_ioctl(
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
		process_register(current->tgid, msg.service_name, tracker_priv);
		break;
	case SPAN_LATENCY_TRACKER_MODULE_UNREGISTER:
		process_unregister(current->tgid);
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

int span_latency_tracker_setup_proc_priv(struct span_latency_tracker* tracker_priv)
{
	int ret = 0;

	tracker_priv->proc_dentry = proc_create_data(USERSPACE_TRACKER_PROC,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
		NULL, &span_latency_tracker_fops, tracker_priv);

	if (!tracker_priv->proc_dentry) {
		printk(KERN_ERR "Error creating userspace tracker control file.\n");
		ret = -ENOMEM;
	}
	return ret;
}

int span_latency_tracker_setup_debug_priv(struct span_latency_tracker* tracker_priv,
	struct dentry* dir)
{
	if (dir == NULL) {
		printk(KERN_WARNING "Error creating tracker debugfs file.\n");
		return -ENOMEM;
	}
	tracker_priv->debug_dentry = dir;
	return 0;
}



