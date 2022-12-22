#include <linux/module.h>
//#include <linux/relay.h>
//#include <linux/debugfs.h>
#include "span_latency_relay.h"

static size_t	subbuf_size = 8225;
static size_t	n_subbufs = 4096;
static int		suspended;
static int		dropped;


/*
 * file_create() callback.  Creates relay file in debugfs.
 */
static
struct dentry* create_buf_file_handler(const char* filename, struct dentry* parent,
	umode_t mode, struct rchan_buf* buf, int* is_global)
{
	struct dentry* buf_file;

	buf_file = debugfs_create_file(filename, mode, parent, buf,
		&relay_file_operations);
	*is_global = 1;

	return buf_file;
}

/*
 * file_remove() default callback.  Removes relay file in debugfs.
 */
static
int remove_buf_file_handler(struct dentry* dentry)
{
	debugfs_remove(dentry);
	return 0;
}

/*
 * subbuf_start() relayfs callback.
 *
 * Defined so that we can 1) reserve padding counts in the sub-buffers, and
 * 2) keep a count of events dropped due to the buffer-full condition.
 */
static
int subbuf_start_handler(struct rchan_buf* buf,
	void* subbuf,
	void* prev_subbuf,
	size_t prev_padding)
{
	if (relay_buf_full(buf)) {
		if (!suspended) {
			suspended = 1;
			printk(KERN_DEBUG "CPU %d buffer full!!!\n", smp_processor_id());
		}
		dropped++;

		/* stop logging */
		return 0;
	}
	else if (suspended) {
		suspended = 0;
		printk(KERN_DEBUG "CPU %d buffer no longer full.\n", smp_processor_id());
	}

	/* Why reserving bytes ?! */
	//subbuf_start_reserve(buf, sizeof(unsigned int));

	/* continue logging */
	return 1;
}

/*
 * relayfs callbacks
 */
static
struct rchan_callbacks rchann_callbacks =
{
	.subbuf_start = subbuf_start_handler,
	.create_buf_file = create_buf_file_handler,
	.remove_buf_file = remove_buf_file_handler,
};


int span_latency_tracker_setup_relay_channel(struct rchan** channel,
	unsigned int id, struct dentry* debug_dir)
{
	char buf[16];

	if (!debug_dir)
		return -ENODEV;

	snprintf(buf, sizeof(buf), "rchan-%u-", id);
	(*channel) = relay_open(buf, debug_dir, subbuf_size, n_subbufs,
		&rchann_callbacks, NULL);

	if (!(*channel)) {
		printk(KERN_ERR "Relay channel creation failed\n");
		return -ENOMEM;
	}

	return 0;
}

void span_latency_tracker_destroy_channel(struct rchan* channel)
{
	WARN_ON_ONCE(channel == NULL);
	if(channel)
		relay_close(channel);
}