/*
 * Process tracking object.
 *
 * Copyright (c) 2007 Alan Robertson
 * Author:	Alan Robertson <alanr@unix.sh>
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

#ifndef _REPLYTRACK_H
#	define _REPLYTRACK_H
#include <sys/types.h>
#include <sys/times.h>
#include <clplumbing/longclock.h>
#include <clplumbing/cl_uuid.h>

/*
 * We track replies - so we can tell when all expected replies were received.
 *
 * There is a problem in clusters where a message is sent to each node, and a
 * reply is expected from each node of knowing when all the replies have been
 * received.
 *
 * If all nodes are up, it's easy to see when all replies are received.
 * But, if some nodes are down, we really don't want to wait for a timeout
 * before we decide that we've gotten all the replies we're going to get,
 * since nodes can be down for potentially very long periods of time, and
 * waiting for a long timeout can delay things a great deal again and
 * again - causing significant delays and user frustration.
 *
 * That's where these functions come in!
 * Instead, inform these functions what nodes are up and what ones are down,
 * and when you receive a reply, and it will tell you when you've gotten
 * them all - managing all that tedious bookwork for you.
 */

typedef enum _replytrack_completion_type	replytrack_completion_type_t;
typedef enum _nodetrack_change			nodetrack_change_t;
typedef struct _replytrack			replytrack_t;
typedef struct _nodetrack			nodetrack_t;
typedef struct _nodetrack_intersection		nodetrack_intersection_t;

/*
 * The levels of logging possible for our process
 */
enum _replytrack_completion_type {
	REPLYT_ALLRCVD = 2,	/* All replies received */
	REPLYT_TIMEOUT,		/* Timeout occurred with replies missing */
};


typedef void  (*replytrack_callback_t) 
(		replytrack_t *		rl
,		gpointer		user_data
,		replytrack_completion_type_t	reason);

typedef void (*replytrack_iterator_t)
(		replytrack_t*	rl
,		gpointer	user_data
,		const char*	node
,		cl_uuid_t	uuid);

typedef void (*nodetrack_iterator_t)
(		nodetrack_t*	rl
,		gpointer	user_data
,		const char*	node
,		cl_uuid_t	uuid);


/*
 * Note:
 * If you use the timeout feature of this code, it relies on you using glib mainloop
 * for your scheduling. timeout_ms should be zero for no timeout.
 */
replytrack_t*	replytrack_new(nodetrack_t*	membership
,		replytrack_callback_t		callback
,		unsigned long			timeout_ms
,		gpointer			user_data);

void		replytrack_del(replytrack_t *rl);
gboolean	replytrack_gotreply(replytrack_t *rl
,		const char * node
,		cl_uuid_t uuid);
		/* Returns TRUE if this was the final expected reply */
/*
 * Iterate over the set of outstanding replies:
 *	return count of how many items in the iteration
 */
int	replytrack_outstanding_iterate(replytrack_t* rl
,		replytrack_iterator_t i, gpointer user_data);
int	replytrack_outstanding_count(replytrack_t* rl);

/*
 * The functions above operate using a view of membership which is established
 * through the functions below.
 *
 * This can either be through the heartbeat low-level membership API, or any
 * other view of membership you wish.  Mentioning a node as either up or down
 * will automatically add that node to our view of potential membership.
 *
 * These functions only support one view of membership per process.
 *
 * The general idea of how to use these functions:
 * Initially:
 *  1) iterate through init membership and call nodetrack_node(up|down) for
 *	each node to start things off.
 *
 * On an ongoing basis:
 *  2) call nodetrack_node_up whenever a node comes up
 *	We expect a reply from nodes that are up.
 *  3) call nodetrack_node_down whenever a node goes down
 *	We don't expect a reply from nodes that are down.
 *
 * For each set of replies you want tracked:
 *  4) Create a replytrack_t for a set of expected replies 
 *  5) call replytrack_gotreply() each time you get an expected reply
 *  6) replist_gotreply() returns TRUE when the final message was received.
 *	(it does this by comparing against the membership as defined below)
 *  7) you will get a callback when timeout occurs or final message is received
 *	n. b.:
 *	No callback function => manage timeouts yourself
 *  8) call replytrack_del() when you're done with the reply list
 *	n. b.:
 *	If you have replies outstanding, and you have a timeout and
 *	a callback function set, you will get a warning for destroying
 *	a replytrack_t object 'prematurely'.
 *      You will also log a warning if you call replytrack_gotreply() after
 *	all replies were received or a timeout occurred.
 *
 */

/*
 * The levels of logging possible for our process
 */
enum _nodetrack_change {
	NODET_UP = 2,	/* This node came up */
	NODET_DOWN,	/* This node went down */
};

typedef void  (*nodetrack_callback_t) 
(		nodetrack_t *		mbr
,		const char *		node
,		cl_uuid_t		u
,		nodetrack_change_t	reason
,		gpointer		user_data);

nodetrack_t*	nodetrack_new(nodetrack_callback_t callback
,		gpointer user_data);
void		nodetrack_del(nodetrack_t*);
gboolean	nodetrack_nodeup(nodetrack_t* mbr, const char * node
,		cl_uuid_t u);
gboolean	nodetrack_nodedown(nodetrack_t* mbr, const char * node
,		cl_uuid_t u);
gboolean	nodetrack_ismember(nodetrack_t* mbr, const char * node
,		cl_uuid_t u);
int		nodetrack_iterate(nodetrack_t* mbr
,		nodetrack_iterator_t i, gpointer user_data);

/* An intesection nodetrack table
 * A node is put into the "intersection" nodetrack_t table when it is in all
 * the underlying constituent nodetrack_t tables, and removed when it is
 * removed from any of them.
 * Note that you can set a callback to be informed when these "intersection"
 * membership changes occur.
 */
nodetrack_intersection_t*
		nodetrack_intersection_new(nodetrack_t** tables, int ntables
,		nodetrack_callback_t callback, gpointer user_data);
void		nodetrack_intersection_del(nodetrack_intersection_t*);
nodetrack_t*	nodetrack_intersection_table(nodetrack_intersection_t*);

#if 0
/*
 * I don't know if this should be in this library, or just in
 * the CCM.  Probably only the CCM _should_ be using it (when I write it)
 */
/*
 * Use of the nodetrack_hb_* functions implies you're using the heartbeat
 * peer-connectivity information as your source of information.  This is
 * really only suitable if you're using heartbeat's low-level group membership
 * for your source of who to expect replies from.
 * If you're using nodetrack_hb_init, this replaces step (1) above.
 */
void	nodetrack_hb_init(void)
/*
 * If you're using nodetrack_hb_statusmsg, just pass it all status messages
 * and all peer-connectivity status messages or even all heartbeat messages
 * (non-status messages will be ignored).
 * This replaces steps (2) and (3) above _if_ you're using heartbeat low
 * level membership for your source of who to expect replies from.
 */
void	nodetrack_hb_statusmsg(struct ha_msg* statusmsg);
#endif /*0*/

#endif
