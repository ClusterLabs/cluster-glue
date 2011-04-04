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

#include <lha_internal.h>
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
#include <assert.h>
#include <ctype.h>

/*
 * Avoid sprintf.  Use snprintf instead, even if you count your bytes.
 * It can detect calculation errors (if used properly)
 * and will not make the security audit tools crazy.
 */

#define		MAX_AUTH_BYTES	64


int msg2netstring_buf(const struct ha_msg*, char*, size_t, size_t*);
int compose_netstring(char*, const char*, const char*, size_t, size_t*);
int is_auth_netstring(const char*, size_t, const char*, size_t);
char* msg2netstring(const struct ha_msg*, size_t*);
int process_netstring_nvpair(struct ha_msg* m, const char* nvpair, int nvlen);
extern int	bytes_for_int(int x);
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

int cl_parse_int(const char *sp, const char *smax, int* len);

int
cl_parse_int(const char *sp, const char *smax, int* len) 
{
	char ch = 0;
	int offset = 0;
	*len = 0;

	errno = 0;
	for( ; sp+offset < smax; offset++) {
		ch = sp[offset] - '0';
		if(ch > 9) { /* ch >= 0 is implied by the data type*/
			break;
		}
		*len *= 10;
		*len += ch;
	}
	
	if(offset == 0) {
		cl_log(LOG_ERR,
		       "cl_parse_int: Couldn't parse an int from: %.5s", sp);
	} 
	return offset;
}

int
compose_netstring(char * s, const char * smax, const char* data,
		  size_t len, size_t* comlen)
{

	char *	sp = s;

	/* 2 == ":" + "," */
	if (s + len + 2 + bytes_for_int(len) > smax) {
		cl_log(LOG_ERR,
		       "netstring pointer out of boundary(compose_netstring)");
		return(HA_FAIL);
	}

	sp += sprintf(sp, "%ld:", (long)len);
	
	if(data){
		memcpy(sp, data, len);
	}
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
	int	ret = HA_OK;

	sp = s;
	smax = s + buflen;

	strcpy(sp, MSG_START_NETSTRING);

	sp += strlen(MSG_START_NETSTRING);

	for (i=0; i < m->nfields; i++) {
		size_t flen;
		int	tmplen;
		
		/* some of these functions in its turn invoke us again */
		ret = fieldtypefuncs[m->types[i]].tonetstring(sp, 
							      smax,
							      m->names[i],
							      m->nlens[i],
							      m->values[i],
							      m->vlens[i],
							      m->types[i],
							      &flen);
		
		if (ret != HA_OK){
			cl_log(LOG_ERR, "encoding msg to netstring failed");
			cl_log_message(LOG_ERR, m);
			return ret;
		}
		
		tmplen = netstring_extra(fieldtypefuncs[m->types[i]].netstringlen(m->nlens[i],
										  m->vlens[i],
										  m->values[i]));
		
		if (flen != tmplen ){
			cl_log(LOG_ERR,"netstring len discrepency: actual usage is %d bytes"
			       "it should use %d", (int)flen, tmplen);			       
		}
		sp +=flen;
		
	}
	
	if (sp + strlen(MSG_END_NETSTRING) > smax){
		cl_log(LOG_ERR, "%s: out of boundary for MSG_END_NETSTRING",
		       __FUNCTION__);
		return HA_FAIL;
	}
	strcpy(sp, MSG_END_NETSTRING);
	sp += sizeof(MSG_END_NETSTRING) -1;
	
	if (sp > smax){
		cl_log(LOG_ERR,
		       "msg2netstring: exceed memory boundary sp =%p smax=%p",
		       sp, smax);
		return(HA_FAIL);
	}
	
	*slen = sp - s;
	return(HA_OK);
}


int get_netstringlen_auth(const struct ha_msg* m);

int get_netstringlen_auth(const struct ha_msg* m)
{
	int len =  get_netstringlen(m) + MAX_AUTH_BYTES;
	return len;
}



static char *
msg2netstring_ll(const struct ha_msg *m, size_t * slen, int need_auth)
{
	int	len;
	char*	s;
	int	authnum;
	char	authtoken[MAXLINE];
	char	authstring[MAXLINE];
	char*	sp;
	size_t	payload_len;
	char*   smax;

	len= get_netstringlen_auth(m) + 1;
	
	/* use MAXUNCOMPRESSED for the in memory size check */
	if (len >= MAXUNCOMPRESSED){
		cl_log(LOG_ERR, "%s: msg is too large; len=%d,"
		       " MAX msg allowed=%d", __FUNCTION__, len, MAXUNCOMPRESSED);
		return NULL;
	}

	s = calloc(1, len);
	if (!s){
		cl_log(LOG_ERR, "%s: no memory for netstring", __FUNCTION__);
		return(NULL);
	}

	smax = s + len;

	if (msg2netstring_buf(m, s, len, &payload_len) != HA_OK){
		cl_log(LOG_ERR, "%s:  msg2netstring_buf() failed", __FUNCTION__);
		free(s);
		return(NULL);
	}
	
	sp = s + payload_len;
	
	if ( need_auth && authmethod){
		int auth_strlen;

		authnum = authmethod(-1, s, payload_len, authtoken,sizeof(authtoken));
		if (authnum < 0){
			cl_log(LOG_WARNING
			       ,	"Cannot compute message authentication!");
			free(s);
			return(NULL);
		}
		
		sprintf(authstring, "%d %s", authnum, authtoken);
		auth_strlen = strlen(authstring);
		if (sp  + 2 + auth_strlen + bytes_for_int(auth_strlen)  >= smax){
			cl_log(LOG_ERR, "%s: out of boundary for auth", __FUNCTION__);
			free(s);
			return NULL;
		}
		sp += sprintf(sp, "%ld:%s,", (long)strlen(authstring), authstring);	
		
	}
	*slen = sp - s;

	return(s);
}

char *
msg2netstring(const struct ha_msg *m, size_t * slen)
{
	char* ret;
	ret = msg2netstring_ll(m, slen, TRUE);
	
	return ret;
	
}
char *
msg2netstring_noauth(const struct ha_msg *m, size_t * slen)
{
	char * ret;
	
	ret =  msg2netstring_ll(m, slen, FALSE);
	
	return ret;
}


/*
 * Peel one string off in a netstring
 */

static int
peel_netstring(const char * s, const char * smax, int* len,
	       const char ** data, int* parselen )
{
	int offset = 0;
	const char *	sp = s;

	if (sp >= smax){
		return(HA_FAIL);
	}

	offset = cl_parse_int(sp, smax, len);
	if (*len < 0 || offset <= 0){
		cl_log(LOG_ERR, "peel_netstring: Couldn't parse an int starting at: %.5s", sp);
		return(HA_FAIL);
	}

	sp = sp+offset;
	while (*sp != ':' && sp < smax) {
		sp ++;
	}

	if (sp >= smax) {
		return(HA_FAIL);
	}

	sp ++;
	
	*data = sp;
	
	sp += (*len);
	if (sp >= smax) {
		return(HA_FAIL);
	}
	if (*sp != ','){
		return(HA_FAIL);
	}
	sp++;

	*parselen = sp - s;

	return(HA_OK);
}


int
process_netstring_nvpair(struct ha_msg* m, const char* nvpair, int nvlen)
{
	
	const char	*name;
	int		nlen;
	const char	*ns_value;
	int		ns_vlen;
	void		*value;
	size_t		vlen;
	int		type;		
	void (*memfree)(void*);
	int		ret = HA_OK;

	assert(*nvpair == '(');
	nvpair++;

	type = nvpair[0] - '0';
	nvpair++;

	/* if this condition is no longer true, change the above to:
	 *   nvpair += cl_parse_int(nvpair, nvpair+nvlen, &type)
	 */
	assert(type >= 0 && type < 10);

	assert(*nvpair == ')');
	nvpair++;
	
	if ((nlen = strcspn(nvpair, EQUAL)) <= 0
	    ||	nvpair[nlen] != '=') {
		if (!cl_msg_quiet_fmterr) {
			cl_log(LOG_WARNING
			       ,	"%s: line doesn't contain '='", __FUNCTION__);
			cl_log(LOG_INFO, "%s", nvpair);
		}
		return(HA_FAIL);
	}
	
	name = nvpair;
	ns_value = name +nlen + 1;
	ns_vlen = nvpair + nvlen - ns_value -3 ;
	if (fieldtypefuncs[type].netstringtofield(ns_value,ns_vlen, &value, &vlen) != HA_OK){
		cl_log(LOG_ERR, "netstringtofield failed in %s", __FUNCTION__);
		return HA_FAIL;
		
	}
	
	memfree = fieldtypefuncs[type].memfree;
	
	if (ha_msg_nadd_type(m  , name, nlen, value, vlen,type)
	    != HA_OK) {
		cl_log(LOG_ERR, "ha_msg_nadd fails(netstring2msg_rec)");	
		ret = HA_FAIL;
	}
	
	
	if (memfree && value){
		memfree(value);
	} else{
		cl_log(LOG_ERR, "netstring2msg_rec:"
		       "memfree or ret_value is NULL");
		ret= HA_FAIL;
	}

	return ret;

	
}
			 

/* Converts a netstring into a message*/
static struct ha_msg *
netstring2msg_rec(const char *s, size_t length, int* slen)
{
	struct ha_msg*	ret = NULL;
	const char *	sp = s;
	const char *	smax = s + length;
	int		startlen;
	int		endlen;
	
	if ((ret = ha_msg_new(0)) == NULL){
		return(NULL);
	}

	startlen = sizeof(MSG_START_NETSTRING)-1;

	if (strncmp(sp, MSG_START_NETSTRING, startlen) != 0) {
		/* This can happen if the sender gets killed */
		/* at just the wrong time... */
		if (!cl_msg_quiet_fmterr) {
			cl_log(LOG_WARNING, "netstring2msg_rec: no MSG_START");
			ha_msg_del(ret);
		}
		return(NULL);
	}else{
		sp += startlen;
	}

	endlen = sizeof(MSG_END_NETSTRING) - 1;

	while (sp < smax && strncmp(sp, MSG_END_NETSTRING, endlen) !=0  ){
		
		const char	*nvpair;
		int		nvlen;	
		int		parselen;
		
		if (peel_netstring(sp , smax, &nvlen, &nvpair,&parselen) != HA_OK){
			cl_log(LOG_ERR
			       ,	"%s:peel_netstring fails for name/value pair", __FUNCTION__);
			cl_log(LOG_ERR, "sp=%s", sp);
			ha_msg_del(ret);
			return(NULL);
		}
		sp +=  parselen;
		
		if (process_netstring_nvpair(ret, nvpair, nvlen) != HA_OK){
			cl_log(LOG_ERR, "%s: processing nvpair failed", __FUNCTION__);
			return HA_FAIL;
		}

	}
	
	
	sp += sizeof(MSG_END_NETSTRING) -1;
	*slen = sp - s;
	return(ret);
	
}


struct ha_msg *
netstring2msg(const char* s, size_t length, int needauth)
{
	const char	*sp;
	struct ha_msg	*msg;
	const char	*smax = s + length;
	int		parselen;
	int		authlen;
	const char	*authstring;
	/*actual string length used excluding auth string*/
	int		slen = 0; /* assign to keep compiler happy */
	
	msg = netstring2msg_rec(s, length, &slen);
	
	if (needauth == FALSE || !authmethod){
		goto out;
	} 
	
	sp =  s + slen;
	
	if (peel_netstring(sp , smax, &authlen, &authstring, &parselen) !=HA_OK){
		cl_log(LOG_ERR,
		       "peel_netstring() error in getting auth string");		
		cl_log(LOG_ERR, "sp=%s", sp);
		cl_log(LOG_ERR, "s=%s", s);
		ha_msg_del(msg);
		return(NULL);
	}

	if (sp + parselen > smax){		
		cl_log(LOG_ERR, " netstring2msg: smax passed");
		ha_msg_del(msg);
		return NULL;
	}

	if (!is_auth_netstring(s, slen, authstring,authlen) ){
		if (!cl_msg_quiet_fmterr) {
			cl_log(LOG_ERR
			       ,	"netstring authentication"
			       " failed, s=%s, autotoken=%s"
			       ,	s, authstring);
			cl_log_message(LOG_ERR, msg);
		}
		ha_msg_del(msg);
		return(NULL);
	}	
	
 out:
	return msg;
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

	memset(authstr, 0, MAXLINE);
	if (authmethod(authwhich, datap, datalen, authstr, MAXLINE)
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
 
