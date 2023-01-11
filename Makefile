ifneq ($(KERNELRELEASE),)

TOP_LT_MODULES_DIR := $(shell dirname $(lastword $(MAKEFILE_LIST)))

include $(TOP_LT_MODULES_DIR)/Makefile.ABI.workarounds

ccflags-y += -I$(src)/include $(EXTCFLAGS) -g -Wall

latency_tracker-objs := tracker.o rculfhash.o rculfhash-mm-chunk.o wfcqueue.o \
	tracker_debugfs.o wrapper/trace-clock.o wrapper/kallsyms.o

latency_tracker-objs += $(shell \
	if [ $(VERSION) -ge 4 -o \
		\( $(VERSION) -eq 3 -a $(PATCHLEVEL) -ge 15 -a $(SUBLEVEL) -ge 0 \) ] ; then \
	echo "lttng-tracepoint.o" ; fi;)

obj-m := latency_tracker.o

obj-m += latency_tracker_begin_end.o

latency_tracker_self_test-objs := trackers/self_test.o
obj-m += latency_tracker_self_test.o

latency_tracker_userspace-objs := trackers/userspace.o wrapper/trace-clock.o tracker_debugfs.o
obj-m += latency_tracker_userspace.o

latency_tracker_spans-objs := wrapper/syscall_name.o trackers/span_latency_relay.o \
	trackers/span_latency_proc.o trackers/span_latency.o wrapper/trace-clock.o tracker_debugfs.o
obj-m += latency_tracker_spans.o

else # KERNELRELEASE

# This part of the Makefile is used when the 'make' command is run in the
# base directory of the latency-tracker sources. It sets some environment and
# calls the kernel build system to build the actual modules.

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CFLAGS = $(EXTCFLAGS)

default: modules

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

endif # KERNELRELEASE
