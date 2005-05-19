/* $Id: cl_malloc.h,v 1.4 2005/05/19 15:50:46 alan Exp $ */
/*
 * ha_malloc.h: malloc utilities for the Linux-HA heartbeat program
 *
 * Copyright (C) 2000 Alan Robertson <alanr@unix.sh>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#ifndef _CLPLUMBING_CLMALLOC_H
#define	 _CLPLUMBING_CLMALLOC_H

typedef struct cl_mem_stats_s {
	unsigned long		numalloc;	/* # of cl_malloc calls */
	unsigned long		numfree;	/* # of cl_free calls */
	unsigned long		numrealloc;	/* # of cl_realloc calls */
	unsigned long		nbytes_req;	/* # malloc bytes req'd */
	unsigned long		nbytes_alloc;	/* # bytes currently allocated
						 */
	unsigned long		mallocbytes;	/* total # bytes malloc()ed */
	unsigned long		arena;		/* Most recent mallinfo */
						/* arena value */
}cl_mem_stats_t;

void*		cl_malloc(size_t size);
void*		cl_calloc(size_t nmemb, size_t size);
void*		cl_realloc(void* oldval, size_t newsize);
char*		cl_strdup(const char *s);
void		cl_free(void *ptr);
int		cl_is_allocated(const void *ptr);
void		cl_malloc_report(void);
void		cl_malloc_setstats(volatile cl_mem_stats_t*);
volatile cl_mem_stats_t* cl_malloc_getstats(void);
void		cl_malloc_forced_for_glib(void);
		/* Call before using any glib functions(!) */
		/* See also: g_mem_set_vtable() */

#define	MALLOCT(t)	((t *) cl_malloc(sizeof(t)))

/* Obsolescent names for cl_malloc, et al... */
#define	ha_malloc	cl_malloc
#define	ha_calloc	cl_calloc
#define	ha_strdup	cl_strdup
#define	ha_free		cl_free
#define	ha_is_allocated	cl_is_allocated
#define	ha_malloc_report	cl_malloc_report
#define	ha_malloc_setstats	cl_malloc_setstats

#endif /* _CLPLUMBING_CLMALLOC_H */
