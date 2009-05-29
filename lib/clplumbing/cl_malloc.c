/*
 * Copyright (C) 2000 Alan Robertson <alanr@unix.sh>
 *
 * This software licensed under the GNU LGPL.
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#define HA_MALLOC_ORIGINAL
#include <lha_internal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif /* HAVE_STDINT_H */
#include <string.h>
#include <errno.h>
#ifndef BSD
#ifdef HAVE_MALLOC_H
#	include <malloc.h>
#endif
#endif
#include <clplumbing/cl_malloc.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/longclock.h>

#include <ltdl.h>

#ifndef _CLPLUMBING_CLMALLOC_NATIVE_H 
static cl_mem_stats_t			default_memstats;
static volatile cl_mem_stats_t *	memstats = &default_memstats;

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
#undef	MARK_PRISTINE
#define	MAKE_GUARD	1	/* Adds 'n' bytes memory - cheap in CPU*/
#define	USE_ASSERTS	1
#define	DUMPONERR	1
#define	RETURN_TO_MALLOC 1
#undef	RETURN_TO_MALLOC

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
 */

#define	HA_MALLOC_MAGIC	0xFEEDBEEFUL
#define	HA_FREE_MAGIC	0xDEADBEEFUL


/*
 * We put a struct cl_mhdr in front of every malloc item.
 * This means each malloc item is at least 12 bytes bigger than it theoretically
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
 *
 * But some architectures have alignment constraints.  For instance, sparc
 * requires that double-word accesses be aligned on double-word boundaries.
 * Thus if the requested space is bigger than a double-word, then cl_mhdr
 * should, for safety, be a double-word multiple (minimum 8bytes, 64bits).

*/

#ifdef HA_MALLOC_TRACK
#	define HA_MALLOC_OWNER 64
struct cl_bucket;
#endif

struct cl_mhdr {
#	ifdef HA_MALLOC_MAGIC
	unsigned long	magic;	/* Must match HA_*_MAGIC */
#endif
#	ifdef HA_MALLOC_TRACK
	char			owner[HA_MALLOC_OWNER];
	struct cl_bucket *	left;
	struct cl_bucket *	right;
	int			dumped;
	longclock_t		mtime;
#endif
	size_t		reqsize;
	int		bucket;
};

struct cl_bucket {
	struct cl_mhdr		hdr;
	struct cl_bucket *	next;
};

#define	NUMBUCKS	12
#define	NOBUCKET	(NUMBUCKS)

static struct cl_bucket*	cl_malloc_buckets[NUMBUCKS];
static size_t	cl_bucket_sizes[NUMBUCKS];
static size_t	buckminpow2 = 0L;

static int cl_malloc_inityet = 0;
static size_t cl_malloc_hdr_offset = sizeof(struct cl_mhdr);

static void*	cl_new_mem(size_t size, int numbuck);
static void	cl_malloc_init(void);
static void	cl_dump_item(const struct cl_bucket*b);

#ifdef MARK_PRISTINE
#	define	PRISTVALUE	0xff
	static int	cl_check_is_pristine(const void* v, unsigned size);
	static void	cl_mark_pristine(void* v, unsigned size);
	static int	pristoff;
#endif

#define	BHDR(p)	 ((struct cl_bucket*)(void*)(((char*)p)-cl_malloc_hdr_offset))
#define	CBHDR(p) ((const struct cl_bucket*)(const void*)(((const char*)p)-cl_malloc_hdr_offset))
#define	MEMORYSIZE(p)(CBHDR(p)->hdr.reqsize)

#define MALLOCSIZE(allocsize) ((allocsize) + cl_malloc_hdr_offset + GUARDSIZE)
#define MAXMALLOC	(SIZE_MAX-(MALLOCSIZE(0)+1))

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
#	define	GUARD_IS_OK(cp)	(memcmp((((const char*)cp)+MEMORYSIZE(cp)),	\
				cl_malloc_guard, sizeof(cl_malloc_guard)) == 0)
#	define CHECK_GUARD_BYTES(cp, msg)	{					\
		if (!GUARD_IS_OK(cp)) {							\
			cl_log(LOG_ERR, "%s: guard corrupted at 0x%lx", msg		\
			,	(unsigned long)cp);					\
			cl_dump_item(CBHDR(cp));					\
			DUMPIFASKED();							\
		}									\
	}
#else
#	define GUARDSIZE	0
#	define ADD_GUARD(cp)	/* */
#	define GUARD_IS_OK(cp)	(1)
#	define CHECK_GUARD_BYTES(cp, msg)	/* */
#endif

#define	MALLOCROUND	4096	/* Round big mallocs up to a multiple of this size */


#ifdef HA_MALLOC_TRACK

static struct cl_bucket *	cl_malloc_track_root = NULL;

static void
cl_ptr_tag(void *ptr, const char *file, const char *function, const int line)
{
	struct cl_bucket*	bhdr = BHDR(ptr);
	snprintf(bhdr->hdr.owner, HA_MALLOC_OWNER, "%s:%s:%d",
			file, function, line);
}

static void
cl_ptr_track(void *ptr)
{
	struct cl_bucket*	bhdr = BHDR(ptr);

#if defined(USE_ASSERTS)
	g_assert(bhdr->hdr.left == NULL);
	g_assert(bhdr->hdr.right == NULL);
	g_assert((cl_malloc_track_root == NULL) || (cl_malloc_track_root->hdr.left == NULL));
#endif

	bhdr->hdr.dumped = 0;
	bhdr->hdr.mtime = time_longclock();

	if (cl_malloc_track_root == NULL) {
		cl_malloc_track_root = bhdr;
	} else {
		bhdr->hdr.right = cl_malloc_track_root;
		cl_malloc_track_root->hdr.left = bhdr;
		cl_malloc_track_root = bhdr;
	}
}

static void
cl_ptr_release(void *ptr)
{
	struct cl_bucket*	bhdr = BHDR(ptr);

/*	cl_log(LOG_DEBUG, "cl_free: Freeing memory belonging to %s"
	,		bhdr->hdr.owner); */
	
#if defined(USE_ASSERTS)
	g_assert(cl_malloc_track_root != NULL);
	g_assert(cl_malloc_track_root->hdr.left == NULL);
#endif

	if (bhdr->hdr.left != NULL) {
		bhdr->hdr.left->hdr.right=bhdr->hdr.right;
	}
	
	if (bhdr->hdr.right != NULL) {
		bhdr->hdr.right->hdr.left=bhdr->hdr.left;
	}
	
	if (cl_malloc_track_root == bhdr) {
		cl_malloc_track_root=bhdr->hdr.right;
	}

	bhdr->hdr.left = NULL;
	bhdr->hdr.right = NULL;
}

static void
cl_ptr_init(void)
{
	cl_malloc_track_root = NULL;
}

int
cl_malloc_dump_allocated(int log_level, gboolean filter)
{
	int lpc = 0;
	struct cl_bucket*	cursor = cl_malloc_track_root;
	longclock_t		time_diff;

	cl_log(LOG_INFO, "Dumping allocated memory buffers:");
	
	while (cursor != NULL) {
		if(filter && cursor->hdr.dumped) {

		} else if(log_level > LOG_DEBUG) {
		} else if(filter) {
			lpc++;
			cl_log(log_level, "cl_malloc_dump: %p owner %s, size %d"
			,	cursor+cl_malloc_hdr_offset
			,	cursor->hdr.owner
			,	(int)cursor->hdr.reqsize);
		} else {
			lpc++;
			time_diff = sub_longclock(time_longclock(), cursor->hdr.mtime);
			cl_log(log_level, "cl_malloc_dump: %p owner %s, size %d, dumped %d, age %lu ms"
			,	cursor+cl_malloc_hdr_offset
			,	cursor->hdr.owner
			,	(int)cursor->hdr.reqsize
			,	cursor->hdr.dumped
			,	longclockto_long(time_diff));
		}
		cursor->hdr.dumped = 1;
		cursor = cursor->hdr.right;
	}
	
	cl_log(LOG_INFO, "End dump.");
	return lpc;
}
#endif
static const int LogTable256[] = 
{
  0, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3,
  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7
};
#define	POW2BYTE(b)	(LogTable256[b])
#define BYTE3(i)	(((i)&0xFF000000)>>24)
#define BYTE2(i)	(((i)&0x00FF0000)>>16)
#define BYTE1(i)	(((i)&0x0000FF00)>>8)
#define BYTE0(i)	 ((i)&0x000000FF)

/* Works for malloc bucket sizes up to 2^8 */
#define POW21BYTE(i)	(POW2BYTE(BYTE0(i)))

/* Works for malloc bucket sizes up to 2^16 */
#define POW22BYTE(i)	((BYTE1(i) != 0x00)? (POW2BYTE(BYTE1(i))+8)	\
			:	(POW21BYTE(i)))

/* Works for malloc bucket sizes up to 2^24 */
#define POW23BYTE(i)	((BYTE2(i) != 0x00)? (POW2BYTE(BYTE2(i))+16)	\
			:	POW22BYTE(i))

/* Works for malloc bucket sizes up to 2^32 */
#define POW24BYTE(i)	((BYTE3(i) != 0x00)? (POW2BYTE(BYTE3(i))+24)	\
			:	POW23BYTE(i))

/* #define	INT2POW2(i)	POW24BYTE(i)	/ * This would allow 2G in our largest malloc chain */
						/* which I don't think we need */
#define	INT2POW2(i)	POW23BYTE(i)	/* This allows up to about 16 Mbytes in our largest malloc chain */
					/* and it's a little faster than the one above */


/*
 * cl_malloc: malloc clone
 */

void *
cl_malloc(size_t size)
{
#if 0
	int			j;
#endif
	int			numbuck = NOBUCKET;
	struct cl_bucket*	buckptr = NULL;
	void*			ret;

	if(!size) {
		cl_log(LOG_ERR
		,	"%s: refusing to allocate zero sized block"
		,	__FUNCTION__
		);
		return NULL;
	}
	if (size > MAXMALLOC) {
		return NULL;
	}
	if (!cl_malloc_inityet) {
		cl_malloc_init();
	}

#if 1
	/*
	 * NOTE: This restricts bucket sizes to be powers of two
	 * - which is OK with me - and how the code has always worked :-D
	 */
	numbuck = INT2POW2(size-1)-buckminpow2;
	numbuck = MAX(0, numbuck);
	if (numbuck < NUMBUCKS) {
		if (size <= cl_bucket_sizes[numbuck]
		||	(numbuck > 0 && size <= (cl_bucket_sizes[numbuck]/2))) {
			buckptr = cl_malloc_buckets[numbuck];
		}else{
			cl_log(LOG_ERR
			,	"%s: bucket size bug: %lu bytes in %lu byte bucket #%d"
			,	__FUNCTION__
			,	(unsigned long)size
			,	(unsigned long)cl_bucket_sizes[numbuck]
			,	numbuck);
		
		}
	}
#else
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
#endif

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
			memstats->nbytes_alloc
			+=	MALLOCSIZE(cl_bucket_sizes[numbuck]);
		}
		
	}

	if (ret && memstats) {
#if 0 && defined(HAVE_MALLINFO)
		/* mallinfo is too expensive to use :-( */
		struct mallinfo	i = mallinfo();
		memstats->arena = i.arena;
#endif
		memstats->numalloc++;
	}
	if (ret) {
#ifdef HA_MALLOC_TRACK
		/* If we were _always_ called via the wrapper functions,
		 * this wouldn't be necessary, but we aren't, some use
		 * function pointers directly to cl_malloc() */
		cl_ptr_track(ret);
		cl_ptr_tag(ret, "cl_malloc.c", "cl_malloc", 0);
#endif
		ADD_GUARD(ret);
	}
	return(ret);
}

int
cl_is_allocated(const void *ptr)
{
#ifdef HA_MALLOC_MAGIC
	if (NULL == ptr || CBHDR(ptr)->hdr.magic != HA_MALLOC_MAGIC) {
		return FALSE;
	}else if (GUARD_IS_OK(ptr)) {
		return TRUE;
	}
	cl_log(LOG_ERR
	,	"cl_is_allocated: supplied storage is guard-corrupted at 0x%lx"
	,	(unsigned long)ptr);
	cl_dump_item(CBHDR(ptr));
	DUMPIFASKED();
	return FALSE;
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
#ifdef HA_MALLOC_TRACK
	cl_ptr_release(ptr);
#endif
	bucket = bhdr->hdr.bucket;
#ifdef HA_MALLOC_MAGIC
	bhdr->hdr.magic = HA_FREE_MAGIC;
#endif

	/*
	 * Return it to the appropriate bucket (linked list), or just free
	 * it if it didn't come from one of our lists...
	 */

#ifndef RETURN_TO_MALLOC
	if (bucket >= NUMBUCKS) {
#endif
#ifdef	MARK_PRISTINE
		/* Is this size right? */
		cl_mark_pristine(ptr, bhdr->hdr.reqsize);
#endif
		if (memstats) {
			memstats->nbytes_req   -= bhdr->hdr.reqsize;
			memstats->nbytes_alloc -= MALLOCSIZE(bhdr->hdr.reqsize);
			memstats->mallocbytes  -= MALLOCSIZE(bhdr->hdr.reqsize);
		}
		free(bhdr);
#ifndef RETURN_TO_MALLOC
	}else{
		int	bucksize = cl_bucket_sizes[bucket];
#if	defined(USE_ASSERTS)
		g_assert(bhdr->hdr.reqsize <= cl_bucket_sizes[bucket]);
#	endif
		if (memstats) {
			memstats->nbytes_req   -= bhdr->hdr.reqsize;
			memstats->nbytes_alloc -= MALLOCSIZE(bucksize);
		}
		bhdr->next = cl_malloc_buckets[bucket];
		cl_malloc_buckets[bucket] = bhdr;
#ifdef	MARK_PRISTINE
		cl_mark_pristine(ptr, bucksize);
#	endif
	}
#endif /* RETURN_TO_MALLOC */
	if (memstats) {
		memstats->numfree++;
	}
}

void*
cl_realloc(void *ptr, size_t newsize)
{
	struct cl_bucket*	bhdr;
	int			bucket;
	size_t			bucksize;

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
	if (newsize == 0) {
		/* realloc() is the most redundant interface ever */
		cl_free(ptr);
		return NULL;
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
	CHECK_GUARD_BYTES(ptr, "cl_realloc");
	
	bucket = bhdr->hdr.bucket;

	/*
	 * Figure out which bucket it came from... If any...
	 */

	if (bucket >= NUMBUCKS) {
		/* Not from our bucket-area... Call realloc... */
		if (memstats) {
			memstats->nbytes_req   -= bhdr->hdr.reqsize;
			memstats->nbytes_alloc -= MALLOCSIZE(bhdr->hdr.reqsize);
			memstats->mallocbytes  -= MALLOCSIZE(bhdr->hdr.reqsize);
			memstats->nbytes_req   += newsize;
			memstats->nbytes_alloc += MALLOCSIZE(newsize);
			memstats->mallocbytes  += MALLOCSIZE(newsize);
		}
#ifdef HA_MALLOC_TRACK
		cl_ptr_release(ptr);
#endif
		bhdr = realloc(bhdr, newsize + cl_malloc_hdr_offset + GUARDSIZE);
		if (!bhdr) {
			return NULL;
		}
#ifdef HA_MALLOC_TRACK
		cl_ptr_track(ptr);
		cl_ptr_tag(ptr, "cl_malloc.c", "realloc", 0);
#endif
		bhdr->hdr.reqsize = newsize;
		ptr = (((char*)bhdr)+cl_malloc_hdr_offset);
		ADD_GUARD(ptr);
		CHECK_GUARD_BYTES(ptr, "cl_realloc - real realloc return value");
		/* Not really a  memory leak...  BEAM thinks so though... */
		return ptr; /*memory leak*/
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
			CHECK_GUARD_BYTES(newret, "cl_realloc - cl_malloc case");
		}
		cl_free(ptr);
		return newret;
	}

	/* Amazing! It fits into the space previously allocated for it! */
	bhdr->hdr.reqsize = newsize;
	if (memstats) {
		memstats->nbytes_req  -= bhdr->hdr.reqsize;
		memstats->nbytes_req  += newsize;
	}
	ADD_GUARD(ptr);
	CHECK_GUARD_BYTES(ptr, "cl_realloc - fits in existing space");
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

	mallocsize = MALLOCSIZE(allocsize);
	if (numbuck == NOBUCKET) {
		mallocsize = (((mallocsize + (MALLOCROUND-1))/MALLOCROUND)*MALLOCROUND);
	}

	if ((hdrret = malloc(mallocsize)) == NULL) {
		return NULL;
	}

	hdrret->hdr.reqsize = size;
	hdrret->hdr.bucket = numbuck;
#ifdef HA_MALLOC_MAGIC
	hdrret->hdr.magic = HA_MALLOC_MAGIC;
#endif
#ifdef HA_MALLOC_TRACK
	hdrret->hdr.left = NULL;
	hdrret->hdr.right = NULL;
	hdrret->hdr.owner[0] = '\0';
	hdrret->hdr.dumped = 0;
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
#ifdef HA_MALLOC_TRACK
		cl_ptr_tag(ret, "cl_malloc.c", "cl_calloc", 0);
#endif
	}
		
	return(ret);
}

#ifdef HA_MALLOC_TRACK
void *
cl_calloc_track(size_t nmemb, size_t size,
		const char *file, const char *function, const int line)
{
	void*			ret;

	ret = cl_calloc(nmemb, size);

	if (ret) {
		cl_ptr_tag(ret, file, function, line);
	}

	return ret;
}

void*
cl_realloc_track(void *ptr, size_t newsize,
		const char *file, const char *function, const int line)
{
	void*			ret;

	ret = cl_realloc(ptr, newsize);

	if (ret) {
		cl_ptr_tag(ret, file, function, line);
	}

	return ret;
}

void *
cl_malloc_track(size_t size, 
		const char *file, const char *function, const int line)
{
	void*	ret;
	
	ret = cl_malloc(size);
	if (ret) {
		/* Retag with the proper owner. */
		cl_ptr_tag(ret, file, function, line);
	}

	return ret;
}

#endif

/*
 * cl_strdup: strdup clone
 */

char *
cl_strdup(const char *s)
{
	void * ret;

	if (!s) {
		cl_log(LOG_ERR, "cl_strdup(NULL)");
		return(NULL);
	}
	ret = cl_malloc((strlen(s) + 1) * sizeof(char));

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
	int	llcount = 1;

	cl_malloc_inityet = 1;

       /* cl_malloc_hdr_offset should be a double-word multiple */
       while (cl_malloc_hdr_offset > (llcount * sizeof(long long))) {
               llcount++;
        }
       cl_malloc_hdr_offset = llcount * sizeof(long long);


	for (j=0; j < NUMBUCKS; ++j) {
		cl_malloc_buckets[j] = NULL;

		cl_bucket_sizes[j] = cursize;
		cursize <<= 1;
	}
 	buckminpow2 = INT2POW2(cl_bucket_sizes[0]-1);
#ifdef MARK_PRISTINE
	{
		struct cl_bucket	b;
		pristoff = (unsigned char*)&(b.next)-(unsigned char*)&b;
		pristoff += sizeof(b.next);
	}
#endif
#ifdef HA_MALLOC_TRACK
	cl_ptr_init();
#endif
}

void
cl_malloc_setstats(volatile cl_mem_stats_t *stats)
{
	if (memstats && stats) {
		*stats = *memstats;
	}
	memstats = stats;
}

volatile cl_mem_stats_t *
cl_malloc_getstats(void)
{
	return	memstats;
}

static void
cl_dump_item(const struct cl_bucket*b)
{
	const unsigned char *	cbeg;
	const unsigned char *	cend;
	const unsigned char *	cp;
	cl_log(LOG_INFO, "Dumping cl_malloc item @ 0x%lx, bucket address: 0x%lx"
	,	((unsigned long)b)+cl_malloc_hdr_offset, (unsigned long)b);
#ifdef HA_MALLOC_TRACK
	cl_log(LOG_INFO, "Owner: %s"
	,	b->hdr.owner);
#endif
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
	cbeg = ((const unsigned char *)b)+cl_malloc_hdr_offset;
	cend = cbeg+b->hdr.reqsize+GUARDSIZE;

	for (cp=cbeg; cp < cend; cp+= sizeof(unsigned)) {
		cl_log(LOG_INFO, "%02x %02x %02x %02x \"%c%c%c%c\""
		,	(unsigned)cp[0], (unsigned)cp[1]
		,	(unsigned)cp[2], (unsigned)cp[3]
		,	cp[0], cp[1], cp[2], cp[3]);
	}
}

/* The only reason these functions exist is because glib uses non-standard
 * types (gsize)in place of size_t.  Since size_t is 64-bits on some
 * machines where gsize (unsigned int) is 32-bits, this is annoying.
 */

static gpointer
cl_malloc_glib(gsize n_bytes)
{
	return (gpointer)cl_malloc((size_t)n_bytes);
}

static void
cl_free_glib(gpointer mem)
{
	cl_free((void*)mem);
}

static void *
cl_realloc_glib(gpointer mem, gsize n_bytes)
{
	return cl_realloc((void*)mem, (size_t)n_bytes);
}


/* Call before using any glib functions(!) */
/* See also: g_mem_set_vtable() */
void
cl_malloc_forced_for_glib(void)
{
	static GMemVTable vt = {
		cl_malloc_glib,
		cl_realloc_glib,
		cl_free_glib,
		NULL,
		NULL,
		NULL,
	};
	if (!cl_malloc_inityet) {
		cl_malloc_init();
	}
	g_mem_set_vtable(&vt);
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

#endif /* _CLPLUMBING_CLMALLOC_NATIVE_H */
