#ifndef _LTTNG_WRAPPER_SYSCALL_NAME_H
#define _LTTNG_WRAPPER_SYSCALL_NAME_H

/*
 * wrapper/syscall_name.h
 *
 * Copyright (C) 2015 Julien Desfossez <julien.desfossez@efficios.com>
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

#ifdef CONFIG_KALLSYMS

#include <linux/kallsyms.h>
#include "kallsyms.h"

int wrapper_get_syscall_name(int nr, char *buf);
#else

#include <linux/vmalloc.h>

static inline
void wrapper_kallsyms_lookup(unsigned long addr,
		unsigned long *symbolsize,
		unsigned long *offset,
		char **modname, char *namebuf)
{
	return NULL;
}

static inline
unsigned long wrapper_sys_call_table(int nr)
{
	return 0;
}

/**
 * @brief buf size shoud be 128 or larger
 *
 * @param nr
 * @param buf
 * @return int
 */
static inline
int wrapper_get_syscall_name(int nr, char *buf)
{
	return -1;
}
#endif

#endif /* _LTTNG_WRAPPER_SYSCALL_NAME_H */
