/* $Id: cl_malloc.c,v 1.7 2005/02/07 02:09:21 alan Exp $ */
#include <portability.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifndef BSD
#ifdef HAVE_MALLOC_H
#	include <malloc.h>
#endif
#endif
#include <clplumbing/cl_malloc.h>
#include <clplumbing/cl_log.h>

#include <ltdl.h>

static volatile cl_mem_stats_t *	memstats = NULL;

/*
 * Compile time malloc debugging switches:
 *
 * MARK_PRISTINE - puts known byte pattern in freed memory
 *			Good at finding "use after free" cases
 *			Cheap in memory, but expensive in CPU
 *
 * MAKE_GUARD	 - puts a known pattern *after* allocated memory
 *			Good at finding overrun problems after the fact
 *			Cheap in CPU, adds a few bytes to each malloc item
 *
 */

#define	MARK_PRISTINE	1	/* Expensive in CPU time */
#define	MAKE_GUARD	1	/* Adds 'n' bytes memory - cheap in CPU*/
#define	USE_ASSERTS	1
#define	DUMPONERR	1

#ifndef DUMPONERR
#	define	DUMPIFASKED()	/* nothing */
#else
#	define	DUMPIFASKED() 	{abort();}
#endif


/*
 *
 *	Malloc wrapper functions
 *
 *	I wrote these so we can better track memory leaks, etc. and verify
 *	that the system is stable in terms of memory usage.
 *
 *	For our purposes, these functions are a somewhat faster than using
 *	malloc directly (although they use a bit more memory)
 *
 *	The general strategy is loosely related to the buddy system, 
 *	except very simple, well-suited to our continuous running
 *	nature, and the constancy of the requests and messages.
 *
 *	We keep an array of linked lists, each for a different size
 *	buffer.  If we need a buffer larger than the largest one provided
 *	by the list, we go directly to malloc.
 *
 *	Otherwise, we keep return them to the appropriate linked list
 *	when we're done with them, and reuse them from the list.
 *
 *	We never coalesce buffers on our lists, and we never free them.
 *
 *	It's very simple.  We get usage stats.  It makes me happy.
 *
 *
 * Copyright (C) 2000 Alan Robertson <alanr@unix.sh>
 *
 * This software licensed under the GNU LGPL.
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

#define	HA_MALLOC_MAGIC	0xFEEDBEEFUL
#define	HA_FREE_MAGIC	0xDEADBEEFUL


/*
 * We put a struct cl_mhdr in front of every malloc item.
 * This means each malloc item is 12 bytes bigger than it theoretically
 * needs to be.  But, it allows this code to be fast and recognize
 * multiple free attempts, and memory corruption *before* the object
 *
 * It's probably possible to combine these fields a bit,
 * since bucket and reqsize are only needed for allocated items,
 * both are bounded in value, and fairly strong integrity checks apply
 * to them.  But then we wouldn't be able to tell *quite* as reliably
 * if someone gave us an item to free that we didn't allocate...
 *
 * Could even make the bucket and reqsize objects into 16-bit ints...
 *
 * The idea of getting it all down into 32-bits of overhead is
 * an interesting thought...
 */

struct cl_mhdr {
#	ifdef HA_MALLOC_MAGIC
	unsigned long	magic;	/* Must match HA_*_MAGIC */
#endif
	size_t		reqsize;
	int		bucket;
};

struct cl_bucket {
	struct cl_mhdr		hdr;
	struct cl_bucket *	next;
};


#define	NUMBUCKS	8
#define	NOBUCKET	(NUMBUCKS)

static struct cl_bucket*	cl_malloc_buckets[NUMBUCKS];
static size_t	cl_bucket_sizes[NUMBUCKS];

static int cl_malloc_inityet = 0;
static size_t cl_malloc_hdr_offset = sizeof(struct cl_mhdr);

void*		cl_malloc(size_t size);
static void*	cl_new_mem(size_t size, int numbuck);
void*		cl_calloc(size_t nmemb, size_t size);
void		cl_free(void *ptr);
static void	cl_malloc_init(void);
static void	cl_dump_item(struct cl_bucket*b);

#ifdef MARK_PRISTINE
#	define	PRISTVALUE	0xff
	static int	cl_check_is_pristine(const void* v, unsigned size);
	static void	cl_mark_pristine(void* v, unsigned size);
	static int	pristoff;
#endif

#define	BHDR(p)	 ((struct cl_bucket*)(void*)(((char*)p)-cl_malloc_hdr_offset))
#define	CBHDR(p) ((const struct cl_bucket*)(const void*)(((const char*)p)-cl_malloc_hdr_offset))
#define	MEMORYSIZE(p)(CBHDR(p)->hdr.reqsize)

#ifdef MAKE_GUARD
#	define GUARDLEN 4
	static const unsigned char cl_malloc_guard[] =
#if GUARDLEN == 1
	{0xA5};
#endif
#if GUARDLEN == 2
	{0x5A, 0xA5};
#endif
#if GUARDLEN == 4
	{0x5A, 0xA5, 0x5A, 0xA5};
#endif
#	define GUARDSIZE	sizeof(cl_malloc_guard)
#	define	ADD_GUARD(cp)	(memcpy((((char*)cp)+MEMORYSIZE(cp)), cl_malloc_guard, sizeof(cl_malloc_guard)))
#	define	GUARD_IS_OK(cp)	(memcmp((((char*)cp)+MEMORYSIZE(cp)), cl_malloc_guard, sizeof(cl_malloc_guard)) == 0)
#else
#	define GUARDSIZE	0
#	define ADD_GUARD(cp)	/* */
#	define GUARD_IS_OK(cp)	(1)
#endif



/*
 * cl_malloc: malloc clone
 */

void *
cl_malloc(size_t size)
{
	int			j;
	int			numbuck = NOBUCKET;
	struct cl_bucket*	buckptr = NULL;
	void*			ret;

	if (!cl_malloc_inityet) {
		cl_malloc_init();
	}

	/*
	 * Find which bucket would have buffers of the requested size
	 */
	for (j=0; j < NUMBUCKS; ++j) {
		if (size <= cl_bucket_sizes[j]) {
			numbuck = j;
			buckptr = cl_malloc_buckets[numbuck];
			break;
		}
	}

	/*
	 * Pull it out of the linked list of free buffers if we can...
	 */

	if (buckptr == NULL) {
		ret = cl_new_mem(size, numbuck);
	}else{
		cl_malloc_buckets[numbuck] = buckptr->next;
		buckptr->hdr.reqsize = size;
		ret = (((char*)buckptr)+cl_malloc_hdr_offset);
		
#ifdef MARK_PRISTINE
		{
			int	bucksize = cl_bucket_sizes[numbuck];
			if (!cl_check_is_pristine(ret,	bucksize)) {
				cl_log(LOG_ERR
				,	"attempt to allocate memory"
				" which is not pristine.");
				cl_dump_item(buckptr);
				DUMPIFASKED();
			}
		}
#endif

#ifdef HA_MALLOC_MAGIC
		switch (buckptr->hdr.magic) {

			case HA_FREE_MAGIC:
				break;

			case HA_MALLOC_MAGIC:
				cl_log(LOG_ERR
				,	"attempt to allocate memory"
				" already allocated at 0x%lx"
				,	(unsigned long)ret);
				cl_dump_item(buckptr);
				DUMPIFASKED();
				ret=NULL;
				break;

			default:
				cl_log(LOG_ERR
				, "corrupt malloc buffer at 0x%lx"
				,	(unsigned long)ret);
				cl_dump_item(buckptr);
				DUMPIFASKED();
				ret=NULL;
				break;
		}
		buckptr->hdr.magic = HA_MALLOC_MAGIC;
#endif /* HA_MALLOC_MAGIC */
		if (memstats) {
			memstats->nbytes_req += size;
			memstats->nbytes_alloc+=cl_bucket_sizes[numbuck];
		}
		
	}

	if (ret && memstats) {
#ifdef HAVE_MALLINFO
		struct mallinfo	i = mallinfo();
		memstats->arena = i.arena;
#endif
		memstats->numalloc++;
	}
	if (ret) {
		ADD_GUARD(ret);
	}
	return(ret);
}

int
cl_is_allocated(const void *ptr)
{

#ifdef HA_MALLOC_MAGIC
	return (ptr && CBHDR(ptr)->hdr.magic == HA_MALLOC_MAGIC);
#else
	return (ptr != NULL);
#endif
}

/*
 * cl_free: "free" clone
 */

void
cl_free(void *ptr)
{
	int			bucket;
	struct cl_bucket*	bhdr;

	if (!cl_malloc_inityet) {
		cl_malloc_init();
	}

	if (ptr == NULL) {
		cl_log(LOG_ERR, "attempt to free NULL pointer in cl_free()");
		DUMPIFASKED();
		return;
	}

	/* Find the beginning of our "hidden" structure */

	bhdr = BHDR(ptr);

#ifdef HA_MALLOC_MAGIC
	switch (bhdr->hdr.magic) {
		case HA_MALLOC_MAGIC:
			break;

		case HA_FREE_MAGIC:
			cl_log(LOG_ERR
			,	"cl_free: attempt to free already-freed"
			" object at 0x%lx"
			,	(unsigned long)ptr);
			cl_dump_item(bhdr);
			DUMPIFASKED();
			return;
			break;
		default:
			cl_log(LOG_ERR, "cl_free: Bad magic number"
			" in object at 0x%lx"
			,	(unsigned long)ptr);
			cl_dump_item(bhdr);
			DUMPIFASKED();
			return;
			break;
	}
#endif
	if (!GUARD_IS_OK(ptr)) {
		cl_log(LOG_ERR
		,	"cl_free: attempt to free guard-corrupted"
		" object at 0x%lx", (unsigned long)ptr);
		cl_dump_item(bhdr);
		DUMPIFASKED();
		return;
	}
	bucket = bhdr->hdr.bucket;
#ifdef HA_MALLOC_MAGIC
	bhdr->hdr.magic = HA_FREE_MAGIC;
#endif

	/*
	 * Return it to the appropriate bucket (linked list), or just free
	 * it if it didn't come from one of our lists...
	 */

	if (bucket >= NUMBUCKS) {
		if (memstats) {
			if (memstats->nbytes_alloc >= bhdr->hdr.reqsize) {
				memstats->nbytes_req   -= bhdr->hdr.reqsize;
				memstats->nbytes_alloc -= bhdr->hdr.reqsize;
				memstats->mallocbytes  -= bhdr->hdr.reqsize;
			}
		}
		free(bhdr);
	}else{
		int	bucksize = cl_bucket_sizes[bucket];
#if defined(USE_ASSERTS)
		g_assert(bhdr->hdr.reqsize <= cl_bucket_sizes[bucket]);
#endif
		if (memstats) {
			if (memstats->nbytes_alloc >= bhdr->hdr.reqsize) {
				memstats->nbytes_req  -= bhdr->hdr.reqsize;
				memstats->nbytes_alloc-= bucksize;
			}
		}
		bhdr->next = cl_malloc_buckets[bucket];
		cl_malloc_buckets[bucket] = bhdr;
#ifdef MARK_PRISTINE
		cl_mark_pristine(ptr, bucksize);
#endif
	}
	if (memstats) {
		memstats->numfree++;
	}
}

void*
cl_realloc(void *ptr, size_t newsize)
{
	struct cl_bucket*	bhdr;
	int			bucket;
	int			bucksize;

	if (!cl_malloc_inityet) {
		cl_malloc_init();
	}

	if (memstats) {
		memstats->numrealloc++;
	}
	if (ptr == NULL) {
		/* NULL is a legal 'ptr' value for realloc... */
		return cl_malloc(newsize);
	}

	/* Find the beginning of our "hidden" structure */

	bhdr = BHDR(ptr);

#ifdef HA_MALLOC_MAGIC
	switch (bhdr->hdr.magic) {
		case HA_MALLOC_MAGIC:
			break;

		case HA_FREE_MAGIC:
			cl_log(LOG_ERR
			,	"cl_realloc: attempt to realloc already-freed"
			" object at 0x%lx"
			,	(unsigned long)ptr);
			cl_dump_item(bhdr);
			DUMPIFASKED();
			return NULL;
			break;
		default:
			cl_log(LOG_ERR, "cl_realloc: Bad magic number"
			" in object at 0x%lx"
			,	(unsigned long)ptr);
			cl_dump_item(bhdr);
			DUMPIFASKED();
			return NULL;
			break;
	}
#endif
	if (!GUARD_IS_OK(ptr)) {
		cl_log(LOG_ERR
		,	"cl_realloc: realloc()ing guard-corrupted"
		" object at 0x%lx (!)", (unsigned long)ptr);
		cl_dump_item(bhdr);
		DUMPIFASKED();
	}
	bucket = bhdr->hdr.bucket;

	/*
	 * Figure out which bucket it came from... If any...
	 */

	if (bucket >= NUMBUCKS) {
		if (memstats) {
			if (memstats->nbytes_alloc >= bhdr->hdr.reqsize) {
				memstats->nbytes_req   -= bhdr->hdr.reqsize;
				memstats->nbytes_alloc -= bhdr->hdr.reqsize;
				memstats->mallocbytes  -= bhdr->hdr.reqsize;
			}
			memstats->nbytes_req   += newsize;
			memstats->nbytes_alloc += newsize;
			memstats->mallocbytes  += newsize;
		}
		/* Not from our bucket-area... Just call realloc... */
		return realloc(bhdr, newsize);
	}
	bucksize = cl_bucket_sizes[bucket];
#if defined(USE_ASSERTS)
	g_assert(bhdr->hdr.reqsize <= bucksize);
#endif
	if (newsize > bucksize) {
		/* Need to allocate new space for it */
		void* newret = cl_malloc(newsize);
		if (newret != NULL) {
			memcpy(newret, ptr, bhdr->hdr.reqsize);
		}
		cl_free(ptr);
		return newret;
	}

	/* Amazing! It fits into the space previously allocated for it! */
	bhdr->hdr.reqsize = newsize;
	if (memstats) {
		if (memstats->nbytes_alloc >= bhdr->hdr.reqsize) {
			memstats->nbytes_req  -= bhdr->hdr.reqsize;
		}
		memstats->nbytes_req  += newsize;
	}
	return ptr;
}

/*
 * cl_new_mem:	use the real malloc to allocate some new memory
 */

static void*
cl_new_mem(size_t size, int numbuck)
{
	struct cl_bucket*	hdrret;
	size_t			allocsize;
	size_t			mallocsize;

	if (numbuck < NUMBUCKS) {
		allocsize = cl_bucket_sizes[numbuck];
	}else{
		allocsize = size;
	}

	mallocsize = allocsize + cl_malloc_hdr_offset + GUARDSIZE;

	if ((hdrret = malloc(mallocsize)) == NULL) {
		return NULL;
	}

	hdrret->hdr.reqsize = size;
	hdrret->hdr.bucket = numbuck;
#ifdef HA_MALLOC_MAGIC
	hdrret->hdr.magic = HA_MALLOC_MAGIC;
#endif

	if (memstats) {
		memstats->nbytes_alloc += mallocsize;
		memstats->nbytes_req += size;
		memstats->mallocbytes += mallocsize;
	}
	/* BEAM BUG -- this is NOT a leak */
	return(((char*)hdrret)+cl_malloc_hdr_offset); /*memory leak*/
}


/*
 * cl_calloc: calloc clone
 */

void *
cl_calloc(size_t nmemb, size_t size)
{
	void *	ret = cl_malloc(nmemb*size);

	if (ret != NULL) {
		memset(ret, 0, nmemb*size);
	}
		
	return(ret);
}


/*
 * cl_strdup: strdup clone
 */

char *
cl_strdup(const char *s)
{
	void * ret = cl_malloc((strlen(s) + 1) * sizeof(char));

	if (ret) {
		strcpy(ret, s);
	}
		
	return(ret);
}


/*
 * cl_malloc_init():	initialize our malloc wrapper things
 */

static void
cl_malloc_init()
{
	int	j;
	size_t	cursize = 32;

	cl_malloc_inityet = 1;
	if (cl_malloc_hdr_offset < sizeof(long long)) {
		cl_malloc_hdr_offset = sizeof(long long);
	}
	for (j=0; j < NUMBUCKS; ++j) {
		cl_malloc_buckets[j] = NULL;

		cl_bucket_sizes[j] = cursize;
		cursize <<= 1;
	}
#ifdef MARK_PRISTINE
	{
		struct cl_bucket	b;
		pristoff = (unsigned char*)&(b.next)-(unsigned char*)&b;
		pristoff += sizeof(b.next);
	}
#endif
}

void cl_malloc_setstats(volatile cl_mem_stats_t *stats)
{
	memstats = stats;
}

static void
cl_dump_item(struct cl_bucket*b)
{
	unsigned char *	cbeg;
	unsigned char *	cend;
	unsigned char *	cp;
	cl_log(LOG_INFO, "Dumping cl_malloc item @ 0x%lx, bucket address: 0x%lx"
	,	((unsigned long)b)+cl_malloc_hdr_offset, (unsigned long)b);
#ifdef HA_MALLOC_MAGIC
	cl_log(LOG_INFO, "Magic number: 0x%lx reqsize=%ld"
	", bucket=%d, bucksize=%ld"
	,	b->hdr.magic
	,	(long)b->hdr.reqsize, b->hdr.bucket
	,	(long)(b->hdr.bucket >= NUMBUCKS ? 0 
	:	cl_bucket_sizes[b->hdr.bucket]));
#else
	cl_log(LOG_INFO, "reqsize=%ld"
	", bucket=%d, bucksize=%ld"
	,	(long)b->hdr.reqsize, b->hdr.bucket
	,	(long)(b->hdr.bucket >= NUMBUCKS ? 0 
	:	cl_bucket_sizes[b->hdr.bucket]));
#endif
	cbeg = ((char *)b)+cl_malloc_hdr_offset;
	cend = cbeg+b->hdr.reqsize+GUARDSIZE;

	for (cp=cbeg; cp < cend; cp+= sizeof(unsigned)) {
		cl_log(LOG_INFO, "%02x %02x %02x %02x \"%c%c%c%c\""
		,	(unsigned)cp[0], (unsigned)cp[1]
		,	(unsigned)cp[2], (unsigned)cp[3]
		,	cp[0], cp[1], cp[2], cp[3]);
	}
}
#ifdef MARK_PRISTINE
static int
cl_check_is_pristine(const void* v, unsigned size)
{
	const unsigned char *	cp;
	const unsigned char *	last;
	cp = v;
	last = cp + size;
	cp += pristoff;

	for (;cp < last; ++cp) {
		if (*cp != PRISTVALUE) {
			return FALSE;
		}
	}
	return TRUE;
}
static void
cl_mark_pristine(void* v, unsigned size)
{
	unsigned char *	cp = v;
	memset(cp+pristoff, PRISTVALUE, size-pristoff);
}
#endif
