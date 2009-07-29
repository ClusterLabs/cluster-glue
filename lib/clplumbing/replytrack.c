
/*
 * Reply tracking library.
 *
 * Copyright (c) 2007 Alan Robertson
 * Author:	Alan Robertson <alanr@unix.sh>
 *
 ******************************************************************
 * This library is useful for tracking replies to multicast messages
 * sent to cluster members.  It tracks incremental membership changes
 * according to any desired criteria, and then keeps track of when
 * the last expected reply is received according to the dynamically
 * updated membership as of when the message was sent out.
 ******************************************************************
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

#include <lha_internal.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <memory.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/replytrack.h>
#include <clplumbing/Gmain_timeout.h>

/*
 * 	These are the only data items that go in our GHashTables
 */
struct rt_node_info {
	char *		nodename;
	cl_uuid_t	nodeid;
};

struct node_tables {

	GHashTable*	uuidmap;	/* Keyed by uuid */
	int		uuidcount;
	GHashTable*	namemap;	/* Keyed by nodename*/
	int		namecount;
};
struct _nodetrack {
	struct node_tables	nt;
	int			refcount;
	nodetrack_callback_t	callback;
	gpointer		user_data;
	nodetrack_callback_t	extra_callback;
	gpointer		ext_data;
};

/*
 *	Things we use to track outstanding replies
 *	This is the structure used by the replytrack_t typedef
 */
struct _replytrack {
	replytrack_callback_t	callback;
	gpointer		user_data;
	unsigned		timerid;
	struct node_tables	tables;
	gboolean		expectingmore;
	nodetrack_t*		membership;
};

struct _nodetrack_intersection {
	nodetrack_t**		tables;
	int			ntables;
	nodetrack_callback_t	callback;
	gpointer		user_data;
	nodetrack_t*		intersection;
};

static cl_uuid_t		nulluuid;
static int			nodetrack_t_count = 0;
static int			replytrack_t_count = 0;
static int			replytrack_intersection_t_count = 0;

static struct rt_node_info *
rt_node_info_new(const char * nodename, cl_uuid_t nodeid)
{
	struct rt_node_info*	ret;

	if (!nodename) {
		return NULL;
	}
	ret = MALLOCT(struct rt_node_info);

	if (!ret) {
		return ret;
	}
	ret->nodename = strdup(nodename);
	if (!ret->nodename) {
		free(ret);
		ret = NULL;
		return ret;
	}
	ret->nodeid = nodeid;
	return ret;
}

static void
rt_node_info_del(struct rt_node_info * ni)
{
	if (ni != NULL) {
		if (ni->nodename != NULL) {
			free(ni->nodename);
		}
		memset(ni, 0, sizeof(*ni));
		free(ni);
	}
}

/*
 * namehash cannot be NULL, idhash cannot be NULL, and nodename cannot be NULL
 *
 * 'id' can be a NULL uuid, in which case it goes into only the name table
 * 'nodename' can change over time - in which case we update our tables.
 * It is possible for one nodename to have more than one uuid.
 * We allow for that.
 *
 * Changing the uuid but keeping the nodename the same is considered to be
 * adding a new node with the same nodename.
 *  Exception:  A node with a null uuid is presumed to have acquired a proper
 *  uuid if it is later seen with a non-null UUID
 */

static gboolean
del_node_from_hashtables(struct node_tables *t
,		const char * nodename, cl_uuid_t id)
{
	struct rt_node_info *	entry;
	if (cl_uuid_is_null(&id)) {
		if ((entry = g_hash_table_lookup(t->namemap,nodename))!=NULL){
			g_hash_table_remove(t->namemap, nodename);
			rt_node_info_del(entry);
			t->namecount--;
		}
		return TRUE;
	}
	if ((entry=g_hash_table_lookup(t->uuidmap, &id)) != NULL) {
		g_hash_table_remove(t->uuidmap, &id);
		rt_node_info_del(entry);
		t->uuidcount--;
	}
	return TRUE;
}


static gboolean
add_node_to_hashtables(struct node_tables * t
,		const char * nodename, cl_uuid_t id)
{
	struct rt_node_info*	idinfo = NULL;

	if (cl_uuid_is_null(&id)) {
		/* Supplied uuid is the null UUID - insert in name table */
		struct rt_node_info*	ninfo;
		if (g_hash_table_lookup(t->namemap, nodename) == NULL) {
			if (NULL == (ninfo = rt_node_info_new(nodename, id))){
				goto outofmem;
			}
			g_hash_table_insert(t->namemap,ninfo->nodename,ninfo);
			t->namecount++;
		}
		return TRUE;
	}

	/* Supplied uuid is not the null UUID */

	if (g_hash_table_lookup(t->uuidmap,&id) == NULL) {
		/* See if a corresponding name is in name map */
		/* If so, delete it - assume uuid was missing before */

		if (g_hash_table_lookup(t->namemap, nodename) != NULL) {
			del_node_from_hashtables(t, nodename, nulluuid);
		}
		/* Not yet in our uuid hash table */
		idinfo = rt_node_info_new(nodename, id);
		if (idinfo == NULL) {
			goto outofmem;
		}
		g_hash_table_insert(t->uuidmap, &idinfo->nodeid, idinfo);
		t->uuidcount++;
	}
	return TRUE;
outofmem:
	cl_log(LOG_ERR, "%s: out of memory", __FUNCTION__);
	return FALSE;
}

static gboolean
create_new_hashtables(struct node_tables*t)
{
	t->namemap = g_hash_table_new(g_str_hash, g_str_equal);
	if (t->namemap == NULL) {
		return FALSE;
	}
	t->uuidmap = g_hash_table_new(cl_uuid_g_hash, cl_uuid_g_equal);
	if (t->uuidmap == NULL) {
		g_hash_table_destroy(t->namemap);
		t->namemap = NULL;
		return FALSE;
	}
	return TRUE;
}

static gboolean
hashtable_destroy_rt_node_info(gpointer key, gpointer rti, gpointer unused)
{
	rt_node_info_del(rti);
	rti = key = NULL;
	return TRUE;
}

static void
destroy_map_hashtable(GHashTable*t)
{
	g_hash_table_foreach_remove(t, hashtable_destroy_rt_node_info,NULL);
	g_hash_table_destroy(t);
	t = NULL;
}

struct tablehelp {
	struct node_tables*	t;
	gboolean		ret;
};

static void
copy_hashtables_helper(gpointer key_unused, gpointer value
,		gpointer user_data)
{
	struct tablehelp *	th = user_data;
	struct rt_node_info*	ni = value;
	if (!add_node_to_hashtables(th->t, ni->nodename, ni->nodeid)) {
		th->ret = FALSE;
	}
}

static gboolean
copy_hashtables(struct node_tables* tin, struct node_tables* tout)
{
	struct tablehelp	newtables;
	if (!create_new_hashtables(tout)){
		return FALSE;
	}
	newtables.t = tout;
	newtables.ret = TRUE;
	
	g_hash_table_foreach(tout->namemap,copy_hashtables_helper,&newtables);
	if (!newtables.ret) {
		return FALSE;
	}
	g_hash_table_foreach(tout->uuidmap,copy_hashtables_helper,&newtables);
	return newtables.ret;
}

static gboolean mbr_inityet = FALSE;
static void
init_global_membership(void)
{
	if (mbr_inityet) {
		return;
	}
	mbr_inityet = TRUE;
	memset(&nulluuid, 0, sizeof(nulluuid));
}

gboolean /* Call us when an expected replier joins / comes up */
nodetrack_nodeup(nodetrack_t * mbr, const char * node, cl_uuid_t uuid)
{
	gboolean	ret;
	ret = add_node_to_hashtables(&mbr->nt, node, uuid);
	if (ret && mbr->callback) {
		mbr->callback(mbr, node, uuid, NODET_UP, mbr->user_data);
	}
	if (mbr->extra_callback) {
		mbr->extra_callback(mbr, node, uuid, NODET_UP,mbr->ext_data);
	}
	return ret;
}

gboolean /* Call us when an expected replier goes down / away */
nodetrack_nodedown(nodetrack_t* mbr, const char* node, cl_uuid_t uuid)
{
	if (mbr->callback) {
		mbr->callback(mbr, node, uuid, NODET_DOWN, mbr->user_data);
	}
	if (mbr->extra_callback) {
		mbr->extra_callback(mbr, node,uuid,NODET_DOWN,mbr->ext_data);
	}
	return del_node_from_hashtables(&mbr->nt, node, uuid);
}

/* This function calls the user's timeout callback */
static gboolean
replytrack_timeout_helper(gpointer rldata)
{
	replytrack_t* rl = rldata;
	rl->expectingmore = FALSE;
	rl->timerid = 0;
	if (rl->callback) {
		rl->callback(rl, rl->user_data, REPLYT_TIMEOUT);
	}
	return FALSE;
}

replytrack_t*	/* replytrack_t constructor */
replytrack_new(nodetrack_t *	membership
,	replytrack_callback_t	callback
,	unsigned long		timeout_ms
,	gpointer		user_data)
{
	replytrack_t*	ret = MALLOCT(replytrack_t);
	if (!ret) {
		return ret;
	}
	if (!copy_hashtables(&membership->nt, &ret->tables)) {
		free(ret);
		ret = NULL;
		return ret;
	}
	replytrack_t_count++;
	ret->membership = membership;
	ret->membership->refcount++;
	ret->callback = callback;
	ret->user_data = user_data;
	ret->expectingmore = TRUE;
	ret->timerid = 0;
	if (timeout_ms != 0 && callback != NULL) {
		ret->timerid = Gmain_timeout_add(timeout_ms
		,	replytrack_timeout_helper, ret);
	}
	return ret;
}

void	/* replytrack_t destructor */
replytrack_del(replytrack_t * rl)
{
	rl->membership->refcount--;
	replytrack_t_count++;
	if (rl->expectingmore && rl->timerid > 0) {
		cl_log(LOG_INFO
		,	"%s: destroying replytrack while still expecting"
		" %d replies"
		, __FUNCTION__
		, (rl->tables.namecount + rl->tables.uuidcount));
	}
	if (rl->timerid > 0) {
		g_source_remove(rl->timerid);
		rl->timerid = 0;
	}
	destroy_map_hashtable(rl->tables.namemap);
	rl->tables.namemap=NULL;
	destroy_map_hashtable(rl->tables.uuidmap);
	rl->tables.uuidmap=NULL;
	memset(&rl, 0, sizeof(rl));
	free(rl);
	rl=NULL;
}

gboolean /* Call replytrack_gotreply when you receive an expected reply */
replytrack_gotreply(replytrack_t*rl, const char * node, cl_uuid_t uuid)
{
	gboolean	lastone;
	del_node_from_hashtables(&rl->tables, node, uuid);
	lastone = (rl->tables.namecount + rl->tables.uuidcount) == 0;
	if (lastone) {
		rl->expectingmore = FALSE;
		if (rl->timerid > 0) {
			g_source_remove(rl->timerid);
			rl->timerid = 0;
		}
		if (rl->callback){
			rl->callback(rl, rl->user_data, REPLYT_ALLRCVD);
		}
	}
	return lastone;
}

struct replytrack_iterator_data {
	replytrack_t*		rlist;
	replytrack_iterator_t	f;
	int			count;
	gpointer		user_data;
};
	

static void /* g_hash_table user-level iteration helper */
replytrack_iterator_helper(gpointer key_unused, gpointer entry
,	gpointer user_data)
{
	struct replytrack_iterator_data*	ri = user_data;
	struct rt_node_info*		ni = entry;
	if (ri && ri->rlist) {
		++ri->count;
		if (ri->f) {
			ri->f(ri->rlist, ri->user_data
			,	ni->nodename, ni->nodeid);
		}
	}
}



int	/* iterate through the outstanding expected replies */
replytrack_outstanding_iterate(replytrack_t* rl
,		replytrack_iterator_t i, gpointer user_data)
{
	struct replytrack_iterator_data id;
	id.rlist = rl;
	id.f = i;
	id.count = 0;
	id.user_data = user_data;
	g_hash_table_foreach(rl->tables.namemap, replytrack_iterator_helper
	,	&id);
	g_hash_table_foreach(rl->tables.uuidmap, replytrack_iterator_helper
	,	&id);
	if (id.count != (rl->tables.namecount + rl->tables.uuidcount)) {
		cl_log(LOG_ERR
		, "%s: iteration count %d disagrees with"
		" (namecount %d+uuidcount %d)"
		,	__FUNCTION__, id.count
		,	rl->tables.namecount,rl->tables.uuidcount);
	}
	return id.count;
}
int	/* return count of outstanding expected replies */
replytrack_outstanding_count(replytrack_t* rl)
{
	return (rl->tables.namecount + rl->tables.uuidcount);
}

nodetrack_t*
nodetrack_new(nodetrack_callback_t callback, gpointer user_data)
{
	nodetrack_t*	ret = MALLOCT(nodetrack_t);
	if (!mbr_inityet) {
		init_global_membership();
	}
	if (!ret) {
		return ret;
	}
	nodetrack_t_count++;
	ret->refcount = 0;
	if (!create_new_hashtables(&ret->nt))  {
		free(ret);
		ret = NULL;
	}
	ret->user_data = user_data;
	ret->callback = callback;
	ret->extra_callback = NULL;
	ret->ext_data = NULL;
	return ret;
}
void
nodetrack_del(nodetrack_t * np)
{
	if (np->refcount) {
		cl_log(LOG_ERR
		, "%s: reply tracking reference count is %d"
		,	__FUNCTION__, np->refcount);
	}
	nodetrack_t_count--;
	destroy_map_hashtable(np->nt.namemap);
	np->nt.namemap=NULL;
	destroy_map_hashtable(np->nt.uuidmap);
	np->nt.uuidmap=NULL;
	memset(np, 0, sizeof(*np));
	free(np);
}

gboolean
nodetrack_ismember(nodetrack_t* mbr, const char * name, cl_uuid_t u)
{
	if (cl_uuid_is_null(&u)) {
		return(g_hash_table_lookup(mbr->nt.namemap, name) != NULL);
	}
	return (g_hash_table_lookup(mbr->nt.uuidmap, &u) != NULL);
}

struct nodetrack_iterator_data {
	nodetrack_t*		rlist;
	nodetrack_iterator_t	f;
	int			count;
	gpointer		user_data;
};
static void /* g_hash_table user-level iteration helper */
nodetrack_iterator_helper(gpointer key_unused, gpointer entry
,	gpointer user_data)
{
	struct nodetrack_iterator_data*	ri = user_data;
	struct rt_node_info*		ni = entry;
	if (ri && ri->rlist) {
		++ri->count;
		if (ri->f) {
			ri->f(ri->rlist, ri->user_data
			,	ni->nodename, ni->nodeid);
		}
	}
}

int	/* iterate through the outstanding expected replies */
nodetrack_iterate(nodetrack_t* rl
,		nodetrack_iterator_t i, gpointer user_data)
{
	struct nodetrack_iterator_data id;
	id.rlist = rl;
	id.f = i;
	id.count = 0;
	id.user_data = user_data;
	g_hash_table_foreach(rl->nt.namemap, nodetrack_iterator_helper
	,	&id);
	g_hash_table_foreach(rl->nt.uuidmap, nodetrack_iterator_helper
	,	&id);
	if (id.count != (rl->nt.namecount + rl->nt.uuidcount)) {
		cl_log(LOG_ERR
		, "%s: iteration count %d disagrees with"
		" (namecount %d+uuidcount %d)"
		,	__FUNCTION__, id.count
		,	rl->nt.namecount,rl->nt.uuidcount);
	}
	return id.count;
}
static void 
intersection_callback
(	nodetrack_t *		mbr
,	const char *		node
,	cl_uuid_t		u
,	nodetrack_change_t	reason
,	gpointer		user_data)
{
	nodetrack_intersection_t*	it = user_data;
	int				j;
	gboolean			allfound = TRUE;

	if (reason == NODET_DOWN) {
		if (nodetrack_ismember(it->intersection, node, u)) {
			nodetrack_nodedown(it->intersection,node,u);
		}
		return;
	}
	for (j=0; j < it->ntables && allfound; ++j) {
		if (nodetrack_ismember(it->tables[j], node, u)) {
			allfound = FALSE;			
		}
	}
	if (allfound) {
		nodetrack_nodeup(it->intersection, node, u);
	}
}

struct li_helper {
	nodetrack_intersection_t*	i;
	gboolean			result;
};

static void
intersection_init_iterator(nodetrack_t* nt
,	gpointer	ghelp
,	const char*	node
,	cl_uuid_t	uuid)
{
	struct li_helper*	help = ghelp;
	gboolean		allfound = TRUE;
	int			j;

	for (j=1; allfound && j < help->i->ntables; ++j) {
		if (!nodetrack_ismember(help->i->tables[j]
		,	node, uuid)) {
			allfound = FALSE;
		}
	}
	if (allfound) {
		nodetrack_nodeup(help->i->intersection, node, uuid);
	}
}

nodetrack_intersection_t*
nodetrack_intersection_new(nodetrack_t** tables, int ntables
,		nodetrack_callback_t callback, gpointer user_data)
{
	nodetrack_intersection_t*	ret;
	int				j;
	ret = MALLOCT(nodetrack_intersection_t);
	if (!ret) {
		return ret;
	}
	ret->intersection = nodetrack_new(callback, user_data);
	if (!ret->intersection)  {
		free(ret);
		ret = NULL;
		return ret;
	}
	ret->tables = tables;
	ret->ntables = ntables;
	ret->callback = callback;
	ret->user_data = user_data;
	for (j=0; j < ntables; ++j) {
		tables[j]->refcount ++;
		tables[j]->ext_data = ret;
		tables[j]->extra_callback = intersection_callback;
	}
	/* Initialize the intersection membership list */
	nodetrack_iterate(tables[0], intersection_init_iterator, ret);
	replytrack_intersection_t_count++;
	return ret;
}
void
nodetrack_intersection_del(nodetrack_intersection_t* p)
{
	int	j;

	for (j=0; j < p->ntables; ++j) {
		p->tables[j]->refcount ++;
	}
	nodetrack_del(p->intersection);
	p->intersection = NULL;
	memset(p, 0, sizeof(*p));
	free(p);
	p = NULL;
	replytrack_intersection_t_count--;
}

nodetrack_t*
nodetrack_intersection_table(nodetrack_intersection_t*p)
{
	return p->intersection;
}
