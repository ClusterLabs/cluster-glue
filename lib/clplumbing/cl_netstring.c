/*
 * netstring implementation
 *
 * Copyright (c) 2003 Guochun Shi <gshi@ncsa.uiuc.edu>
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

#include <portability.h>
#include <heartbeat.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ha_msg.h>
#include <unistd.h>
#include <clplumbing/ipc.h>
#include <clplumbing/netstring.h>
#include <clplumbing/base64.h>

/*
 * Avoid sprintf.  Use snprintf instead, even if you count your bytes.
 * It can detect calculation errors (if used properly)
 * and will not make the security audit tools crazy.
 */


int msg2netstring_buf(const struct ha_msg*, char*, size_t, size_t*);
int compose_netstring(char*, const char*, const char*, size_t, int*);
int is_auth_netstring(const char*, size_t, const char*, size_t);
char* msg2netstring(const struct ha_msg*, size_t*);
struct ha_msg* netstring2msg(const char *, size_t, int);

extern const char *	FT_strings[];

static int (*authmethod)(int whichauth
,	const void * data
,	size_t datalen
,	char * authstr
,	size_t authlen) = NULL;

void
cl_set_authentication_computation_method(int (*method)(int whichauth
,	const void * data
,	size_t datalen
,	char * authstr
,	size_t authlen))
{
	authmethod = method;
}


int
compose_netstring(char * s, const char * smax, const char* data,
		  size_t len, int* comlen)
{

	char *	sp = s;

	/* 3 == ":" + "," + at least one digit number */
	if (s + len + 3 > smax) {
		cl_log(LOG_ERR
		,	"netstring pointer out of boundary(compose_netstring)");
		return(HA_FAIL);
	}

	sp += sprintf(sp, "%ld:", (long)len);

	memcpy(sp, data, len);
	sp += len;
	*sp++ = ',';

	*comlen = sp - s;

	return(HA_OK);
}



/* Converts a message into a netstring */

int
msg2netstring_buf(const struct ha_msg *m, char *s,
		  size_t buflen, size_t * slen)
{
	int	i;
	char *	sp;
	char *	smax;

	char *	datap;
	int	datalen = 0;
	char	authtoken[MAXLINE];
	char	authstring[MAXLINE];
	int	authnum;
	sp = s;
	smax = s + buflen;

	strcpy(sp, MSG_START_NETSTRING);

	sp += strlen(MSG_START_NETSTRING);

	datap = sp;

	for (i=0; i < m->nfields; i++) {
		int comlen;
		size_t llen;

		if (compose_netstring(sp, smax, m->names[i],
				      m->nlens[i], &comlen) != HA_OK){
			cl_log(LOG_ERR
			,	"compose_netstring fails for"
			" name(msg2netstring_buf)");
			return(HA_FAIL);
		}

		sp += comlen;
		datalen +=comlen;


		if (compose_netstring(sp, smax, FT_strings[m->types[i]], 1, 
				      &comlen) != HA_OK) {
			cl_log(LOG_ERR
			, "compose_netstring fails for"
			       " type(msg2netstring_buf)");
			return(HA_FAIL);
		}
		
		sp += comlen;
		datalen +=comlen;
		
		llen = (size_t)m->nlens[i];
		
		if(m->types[i] < sizeof(fieldtypefuncs) 
		   / sizeof(fieldtypefuncs[0])){					
			int (*tonetstring)(char*, char*, void*, size_t, size_t*);			
			tonetstring = fieldtypefuncs[m->types[i]].tonetstring;
			if (!tonetstring || tonetstring(sp, smax, m->values[i], m->vlens[i], &comlen) != HA_OK){
				cl_log(LOG_ERR, "msg2netstring_buf: "
				       "tonetstring() failed, type=%d", m->types[i]);
				return HA_FAIL;
			}
			
			sp += comlen;
			datalen +=comlen;
		}
	}
	

	/* Add authentication */
	
	if ((authnum=authmethod(-1, datap, datalen, authtoken
				,		sizeof(authtoken))) < 0) {
		cl_log(LOG_WARNING
		       ,	"Cannot compute message authentication!");
		return(HA_FAIL);
	}
	sprintf(authstring, "%d %s", authnum, authtoken);
	sp += sprintf(sp, "%ld:%s,", (long)strlen(authstring), authstring);

	strcpy(sp, MSG_END_NETSTRING);
	sp += sizeof(MSG_END_NETSTRING) -1;

	if (sp > smax){
		cl_log(LOG_ERR
		,	"msg2netstring: exceed memory boundary sp =%p smax=%p"
		,	sp, smax);
		return(HA_FAIL);
	}

	*slen = sp - s + 1;
	return(HA_OK);
}

char *
msg2netstring(const struct ha_msg *m, size_t * slen)
{

	int	len;
	void	*s;

	len= get_netstringlen(m) + 1;
	s = ha_calloc(1, len);
	if (!s){
		cl_log(LOG_ERR, "msg2netstring: no memory for netstring");
		return(NULL);
	}

	if (msg2netstring_buf(m, s, len, slen) != HA_OK){
		cl_log(LOG_ERR, "msg2netstring: msg2netstring_buf() failed");
		ha_free(s);
		return(NULL);
	}

	return(s);
}


/*
 * Peel one string off in a netstring
 */

static int
peel_netstring(const char * s, const char * smax, int* len,
	       const char ** data, int* parselen )
{
	const char *	sp = s;

	if (sp >= smax){
		return(HA_FAIL);
	}

	sscanf(sp,"%d", len);

	if (len <= 0){
		return(HA_FAIL);
	}

	while (*sp != ':' && sp < smax) {
		sp ++;
	}

	if (sp >= smax ){
		return(HA_FAIL);
	}

	sp ++;

	*data = sp;

	sp += (*len);
	if (*sp != ','){
		return(HA_FAIL);
	}
	sp++;

	*parselen = sp - s;

	return(HA_OK);
}

/* Converts a netstring into a message*/
struct ha_msg *
netstring2msg(const char *s, size_t length, int need_auth)
{
	struct ha_msg*	ret = NULL;
	const char *	sp = s;
	const char *	smax = s + length;
	int		startlen;
	int		endlen;
	const char *	datap;
	int		datalen = 0;
	int (*netstringtofield)(const void*, size_t, void**, size_t*);			
	void (*memfree)(void*);
	
	if ((ret = ha_msg_new(0)) == NULL){
		return(NULL);
	}

	startlen = sizeof(MSG_START_NETSTRING)-1;

	if (strncmp(sp, MSG_START_NETSTRING, startlen) != 0) {
		/* This can happen if the sender gets killed */
		/* at just the wrong time... */
		if (!cl_msg_quiet_fmterr) {
			cl_log(LOG_WARNING, "netstring2msg: no MSG_START");
			ha_msg_del(ret);
		}
		return(NULL);
	}else{
		sp += startlen;
	}

	endlen = sizeof(MSG_END_NETSTRING) - 1;

	datap = sp;
	while (sp < smax && strncmp(sp, MSG_END_NETSTRING, endlen) !=0  ){
		int		nlen;
		int		vlen;
		const char *	name;
		const char *	value;
		int		parselen;
		int		tmp;

		int		tlen;
		const char *	type;
		int		fieldtype;
		void*		ret_value;
		size_t		ret_vlen;

		tmp = datalen;
		if (peel_netstring(sp , smax, &nlen, &name,&parselen) != HA_OK){
			cl_log(LOG_ERR
			,	"peel_netstring fails for name(netstring2msg)");
			ha_msg_del(ret);
			return(NULL);
		}
		sp +=  parselen;
		datalen += parselen;

		if (strncmp(sp, MSG_END_NETSTRING, endlen) == 0) {
			if (!is_auth_netstring(datap, tmp, name,nlen) ){
				if (!cl_msg_quiet_fmterr) {
					cl_log(LOG_ERR
					,	"netstring authentication"
					" failed, s=%s, autotoken=%s, sp=%s"
					,	s, name, sp);
					cl_log_message(ret);
				}
				ha_msg_del(ret);
				return(NULL);
			}

			goto happyexit;
		}


		if (peel_netstring(sp , smax, &tlen, &type, &parselen) !=HA_OK){
			cl_log(LOG_ERR
			,	"peel_netstring() error in netstring2msg"
			" for type");
			ha_msg_del(ret);
			return(NULL);
		}
		sp +=  parselen;
		datalen += parselen;
		
		
		if (peel_netstring(sp, smax, &vlen, &value, &parselen) !=HA_OK){
			cl_log(LOG_ERR
			,  "peel_netstring() error in netstring2msg for value");
			ha_msg_del(ret);
			return(NULL);
		}
		sp +=  parselen;
		datalen += parselen;
		
		fieldtype = atoi(type);		
		
		if (fieldtype < sizeof(fieldtypefuncs) 
		    / sizeof(fieldtypefuncs[0])){					
			netstringtofield = fieldtypefuncs[fieldtype].netstringtofield;
			memfree = fieldtypefuncs[fieldtype].memfree;
			if (!netstringtofield || netstringtofield(value, vlen,
								  &ret_value, &ret_vlen) != HA_OK){
				cl_log(LOG_ERR, "netstring2msg: "
				       "tonetstring() failed, type=%d", fieldtype);
				return NULL;
			}
		}else {
			cl_log(LOG_ERR, "netstring2msg: wrong type(%d)", fieldtype);
			return NULL;
		}
		
		
		if (ha_msg_nadd_type(ret, name, nlen, ret_value, ret_vlen, fieldtype)
		    != HA_OK) {
			cl_log(LOG_ERR, "ha_msg_nadd fails(netstring2msg)");
			
			if (memfree && ret_value){
				memfree(ret_value);
			} else{
				cl_log(LOG_ERR, "netstring2msg:"
				       "memfree or ret_value is NULL");
			}
			
			ha_msg_del(ret);
			return(NULL);
		}
		
		
		if (memfree && ret_value){
			memfree(ret_value);
		} else{
			cl_log(LOG_ERR, "netstring2msg:"
			       "memfree or ret_value is NULL");
		}
	}
	
	/* if program runs here,
	   the message is generated but
	   no authentication found*/
	  
	if (!need_auth){
		return(ret);
	}else {
		if (!cl_msg_quiet_fmterr) {
			cl_log(LOG_ERR, "no authentication found in netstring");
		}
		ha_msg_del(ret);
		return(NULL);
	}
	


 happyexit:
	return(ret);
	
}

int
is_auth_netstring(const char * datap, size_t datalen,
		  const char * authstring, size_t authlen)
{

	char	authstr[MAXLINE];	/* A copy of authstring */
	int	authwhich;
	char	authtoken[MAXLINE];


	/*
	 * If we don't have any authentication method - everything is authentic...
	 */
	if (!authmethod) {
		return TRUE;
	}
	strncpy(authstr, authstring, MAXLINE);
	authstr[authlen] = 0;
	if (sscanf(authstr, "%d %s", &authwhich, authtoken) != 2) {
		if (!cl_msg_quiet_fmterr) {
			cl_log(LOG_WARNING
			,	"Bad/invalid netstring auth string");
		}
		return(0);
	}


	if (authmethod(authwhich, datap, datalen, authstr, authlen)
	!=	authwhich) {

		if (!cl_msg_quiet_fmterr) {
			cl_log(LOG_WARNING
			,	"Invalid authentication [%d] in message!"
			,	authwhich);
		}
		return(FALSE);
	}

	if (strcmp(authtoken, authstr) == 0) {
		return(TRUE);
	}

	if (!cl_msg_quiet_fmterr) {
		cl_log(LOG_ERR
		,	"authtoken does not match, authtoken=%s, authstr=%s"
		       ,	authtoken, authstr);
	}
	return(FALSE);
}
