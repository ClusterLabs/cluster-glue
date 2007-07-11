/* 
 * netstring_test: Test program for testing the heartbeat binary/struct API
 *
 * Copyright (C) 2000 Guochun Shi <gshi@ncsa.uiuc.edu>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <lha_internal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <syslog.h>
#include <hb_api_core.h>
#include <hb_api.h>

/*
 * A heartbeat API test program...
 */

void NodeStatus(const char * node, const char * status, void * private);
void LinkStatus(const char * node, const char *, const char *, void*);
void gotsig(int nsig);

void
NodeStatus(const char * node, const char * status, void * private)
{
	cl_log(LOG_NOTICE, "Status update: Node %s now has status %s"
	,	node, status);
}

void
LinkStatus(const char * node, const char * lnk, const char * status
,	void * private)
{
	cl_log(LOG_NOTICE, "Link Status update: Link %s/%s now has status %s"
	,	node, lnk, status);
}

int quitnow = 0;
void gotsig(int nsig)
{
	(void)nsig;
	quitnow = 1;
}

#define BUFSIZE 16
extern int netstring_format;

int
main(int argc, char ** argv)
{
	struct ha_msg*	reply;
	struct ha_msg*	pingreq = NULL;
	unsigned	fmask;
	ll_cluster_t*	hb;
	int		msgcount=0;
	char		databuf[BUFSIZE];
	int		i;
#if 0
	char *		ctmp;
	const char *	cval;
	int		j;
#endif
	
	netstring_format = 0;

	cl_log_set_entity(argv[0]);
	cl_log_enable_stderr(TRUE);
	cl_log_set_facility(LOG_USER);
	hb = ll_cluster_new("heartbeat");
	cl_log(LOG_INFO, "PID=%ld", (long)getpid());
	cl_log(LOG_INFO, "Signing in with heartbeat");
	if (hb->llc_ops->signon(hb, "ping")!= HA_OK) {
		cl_log(LOG_ERR, "Cannot sign on with heartbeat");
		cl_log(LOG_ERR, "REASON: %s", hb->llc_ops->errmsg(hb));
		exit(1);
	}

	if (hb->llc_ops->set_nstatus_callback(hb, NodeStatus, NULL) !=HA_OK){
		cl_log(LOG_ERR, "Cannot set node status callback");
		cl_log(LOG_ERR, "REASON: %s", hb->llc_ops->errmsg(hb));
		exit(2);
	}

	if (hb->llc_ops->set_ifstatus_callback(hb, LinkStatus, NULL)!=HA_OK){
		cl_log(LOG_ERR, "Cannot set if status callback");
		cl_log(LOG_ERR, "REASON: %s", hb->llc_ops->errmsg(hb));
		exit(3);
	}

#if 0
	fmask = LLC_FILTER_RAW;
#else
	fmask = LLC_FILTER_DEFAULT;
#endif
	/* This isn't necessary -- you don't need this call - it's just for testing... */
	cl_log(LOG_INFO, "Setting message filter mode");
	if (hb->llc_ops->setfmode(hb, fmask) != HA_OK) {
		cl_log(LOG_ERR, "Cannot set filter mode");
		cl_log(LOG_ERR, "REASON: %s", hb->llc_ops->errmsg(hb));
		exit(4);
	}

	CL_SIGINTERRUPT(SIGINT, 1);
	CL_SIGNAL(SIGINT, gotsig);
	
	pingreq = ha_msg_new(0);
	ha_msg_add(pingreq, F_TYPE, "ping");
	{
		struct ha_msg	*childmsg;
		struct ha_msg	*grandchildmsg;	
		  
		for(i = 0 ;i < BUFSIZE;i ++){
			databuf[i] = 1 +  i ;
		}
		databuf[4] = 0;

		ha_msg_addbin(pingreq, "data",databuf , BUFSIZE);
		
 
		childmsg = ha_msg_new(0);
		ha_msg_add(childmsg, "name","testchild");
		ha_msg_addbin(childmsg, "data",databuf , BUFSIZE);
		
		grandchildmsg = ha_msg_new(0);
		ha_msg_add(grandchildmsg, "name","grandchild");
		ha_msg_addstruct(childmsg, "child",grandchildmsg);

		if( ha_msg_addstruct(pingreq, "child", childmsg) != HA_OK){
			cl_log(LOG_ERR, "adding a child message to the message failed");
			exit(1);
		}
		
	}
	
	cl_log(LOG_INFO, "printing out the pingreq message:");

	ha_log_message(pingreq);
	if (hb->llc_ops->sendclustermsg(hb, pingreq) == HA_OK) {
		cl_log(LOG_INFO, "Sent ping request to cluster");
	}else{
		cl_log(LOG_ERR, "PING request FAIL to cluster");
	}
	errno = 0;
	for(; !quitnow && (reply=hb->llc_ops->readmsg(hb, 1)) != NULL;) {
		const char *	type;
		const char *	orig;
		++msgcount;
		if ((type = ha_msg_value(reply, F_TYPE)) == NULL) {
			type = "?";
		}
		if ((orig = ha_msg_value(reply, F_ORIG)) == NULL) {
			orig = "?";
		}
		cl_log(LOG_INFO, " ");
		cl_log(LOG_NOTICE, "Got message %d of type [%s] from [%s]"
		,	msgcount, type, orig);
		
		if (strcmp(type, "ping") ==0) {
			int datalen = 0;
			const char	*data;
			struct ha_msg	*childmsg;
			
			cl_log(LOG_INFO, "****************************************");
			ha_log_message(reply);
			
			data = cl_get_binary(reply, "data", &datalen);
			if(data){
				cl_log(LOG_INFO, " ");
				cl_log(LOG_INFO, "%d of data received,data=%s", datalen,data);
				for(i = 0; i < datalen; i++){
					if( databuf[i] != data[i]){
						cl_log(LOG_ERR, "data does not match at %d",i);
						break;
					}
				}
				if(i ==  datalen){
					cl_log(LOG_INFO,"data matches");
				}
			}else {
				cl_log(LOG_WARNING, "cl_get_binary failed");				
			}
			
			childmsg = cl_get_struct(reply,"child");
			if(childmsg){
				cl_log(LOG_INFO, " ");
				cl_log(LOG_INFO, "child message found");
				ha_log_message(childmsg);
			}else{
				cl_log(LOG_WARNING, "cl_get_struct failed");
			}			
			
		}
		
#if 1
		{
			struct ha_msg *cpmsg;
			cl_log(LOG_INFO, " ");
			cl_log(LOG_INFO, "****************************************************");
			cl_log(LOG_INFO, "Testing ha_msg_copy():");
			cpmsg = ha_msg_copy(reply);
			cl_log(LOG_INFO, " ");
			cl_log(LOG_INFO, "orginal message is :");
			cl_log(LOG_INFO, " ");
			ha_log_message(reply);
			cl_log(LOG_INFO, " ");
			cl_log(LOG_INFO, "copied message is: ");
			cl_log(LOG_INFO, " ");
			ha_log_message(cpmsg);
			ha_msg_del(cpmsg);
		}

		ha_msg_del(reply); reply=NULL;
#endif		
	}
	
	if (!quitnow) {
		cl_log(LOG_ERR, "read_hb_msg returned NULL");
		cl_log(LOG_ERR, "REASON: %s", hb->llc_ops->errmsg(hb));
	}
	if (hb->llc_ops->signoff(hb, TRUE) != HA_OK) {
		cl_log(LOG_ERR, "Cannot sign off from heartbeat.");
		cl_log(LOG_ERR, "REASON: %s", hb->llc_ops->errmsg(hb));
		exit(10);
	}
	if (hb->llc_ops->delete(hb) != HA_OK) {
		cl_log(LOG_ERR, "Cannot delete API object.");
		cl_log(LOG_ERR, "REASON: %s", hb->llc_ops->errmsg(hb));
		exit(11);
	}
	return 0;
}
