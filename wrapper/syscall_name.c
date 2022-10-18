#include "syscall_name.h"

static char *(*kallsyms_lookup_sym)(unsigned long addr,
		unsigned long *symbolsize,
		unsigned long *offset,
		char **modname, char *namebuf);

static unsigned long *sys_call_table_sym;

static
const char *wrapper_kallsyms_lookup(unsigned long addr,
		unsigned long *symbolsize,
		unsigned long *offset,
		char **modname, char *namebuf)
{

	if (!kallsyms_lookup_sym) {
		kallsyms_lookup_sym = (void *) kallsyms_lookup_funcptr("kallsyms_lookup");
	}

	if (kallsyms_lookup_sym) {
		return kallsyms_lookup_sym(addr, symbolsize, offset, modname,
				namebuf);
	} else {
		return NULL;
	}
}

static
unsigned long wrapper_sys_call_table(int nr)
{
	if(!sys_call_table_sym) {
		sys_call_table_sym = (void *) kallsyms_lookup_dataptr("sys_call_table");
	}
	if (sys_call_table_sym) {
		return (unsigned long) sys_call_table_sym[nr];
	} else {
		return 0;
	}
}

/**
 * @brief buf size shoud be 128 or larger
 *
 * @param nr
 * @param buf
 * @return int
 */
int wrapper_get_syscall_name(int nr, char *buf)
{
	unsigned long addr;

	addr = wrapper_sys_call_table(nr);
	if (!addr)
		return -1;
	wrapper_kallsyms_lookup(addr, NULL, NULL, NULL, buf);
	return 0;
}