/* $Id: cl_msg.c,v 1.19 2004/08/29 04:05:23 msoffen Exp $ */
/*
 * Heartbeat messaging object.
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

#include <portability.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/utsname.h>
#include <ha_msg.h>
#include <unistd.h>
#include <clplumbing/cl_malloc.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/ipc.h>
#include <clplumbing/base64.h>
#include <clplumbing/netstring.h>

#define		MAXMSGLINE	MAXMSG
#define		MINFIELDS	30
#define		CRNL		"\r\n"
#define		MAX_AUTH_BYTES	64


#define		NL_TO_SYM	0
#define		SYM_TO_NL	1
#define		NEEDAUTH	1
#define		NOAUTH		0

static enum cl_msgfmt msgfmt = MSGFMT_NVPAIR;

int		SPECIAL_SYMS[]={
	20,
	21,
	22,
	23,
	24,
	25,
	26,
	27,
	28,
	29
};


const char*
FT_strings[]={
	"0",
	"1",
	"2",
	"3",
	"4",
	"5",
	"6",
	"7",
	"8",
	"9"
};


#undef DOAUDITS
#ifdef DOAUDITS

void ha_msg_audit(const struct ha_msg* msg);

#	define	AUDITMSG(msg)	ha_msg_audit(msg)
#else
#	define	AUDITMSG(msg)	/* Nothing */
#endif

static volatile hb_msg_stats_t*	msgstats = NULL;

extern int		netstring_format;

static struct ha_msg* wirefmt2msg_ll(const char* s, size_t length, int need_auth);
static struct ha_msg* string2msg_ll(const char * s, size_t length, int need_auth, int depth);

void
cl_msg_setstats(volatile hb_msg_stats_t* stats)
{
	msgstats = stats;
}

/* Set default messaging format */
void
cl_set_msg_format(enum cl_msgfmt mfmt)
{
	msgfmt = mfmt;
}

/*
 * This function changes each new line in the input string
 * into a special symbol, or the other way around
 */

static int
convert(char* s, int len, int depth, int direction)
{
	int	i;

	if (direction != NL_TO_SYM && direction != SYM_TO_NL){
		cl_log(LOG_ERR, "convert(): direction not defined!");
		return(HA_FAIL);
	}


	if (depth >= MAXDEPTH ){
		cl_log(LOG_ERR, "convert(): MAXDEPTH exceeded");
		return(HA_FAIL);
	}

	for (i = 0; i < len; i++){

		switch(direction){
		case NL_TO_SYM :
			if (s[i] == '\n'){
				s[i] = SPECIAL_SYMS[depth];
				break;
			}

			if (s[i] == SPECIAL_SYMS[depth]){
				cl_log(LOG_ERR
				, "convert(): special symbol found in string");
				return(HA_FAIL);
			}

			break;

		case SYM_TO_NL:

			if (s[i] == '\n'){
				cl_log(LOG_ERR
				,	"convert(): new line found in"
				" converted string");
				return(HA_FAIL);
			}

			if (s[i] == SPECIAL_SYMS[depth]){
				s[i] = '\n';
				break;
			}
			break;
		default:
			/* nothing, never executed*/;

		}
	}

	return(HA_OK);
}



/* Create a new (empty) message */
struct ha_msg *
ha_msg_new(nfields)
{
	struct ha_msg *	ret;
	int	nalloc;

	ret = MALLOCT(struct ha_msg);
	if (ret) {
		ret->nfields = 0;

		if (nfields > MINFIELDS) {
			nalloc = nfields;
		} else {
			nalloc = MINFIELDS;
		}

		ret->nalloc    = nalloc;
		ret->names     = (char **)ha_calloc(sizeof(char *), nalloc);
		ret->nlens     = (int *)ha_calloc(sizeof(int), nalloc);
		ret->values    = (void **)ha_calloc(sizeof(void *), nalloc);
		ret->vlens     = (size_t *)ha_calloc(sizeof(size_t), nalloc);
		ret->stringlen = sizeof(MSG_START)+sizeof(MSG_END)-1;
		ret->netstringlen = sizeof(MSG_START_NETSTRING)
		+	sizeof(MSG_END_NETSTRING) - 1 + MAX_AUTH_BYTES;
		ret->types	= (int*)ha_calloc(sizeof(int), nalloc);

		if (ret->names == NULL || ret->values == NULL
		||	ret->nlens == NULL || ret->vlens == NULL
		||	ret->types == NULL) {

			cl_log(LOG_ERR, "%s"
			,	"ha_msg_new: out of memory for ha_msg");
			ha_msg_del(ret);
			ret = NULL;
		}else if (msgstats) {
			msgstats->allocmsgs++;
			msgstats->totalmsgs++;
			msgstats->lastmsg = time_longclock();
		}
	}
	return(ret);
}

/* Delete (destroy) a message */
void
ha_msg_del(struct ha_msg *msg)
{
	if (msg) {
		int	j;
		AUDITMSG(msg);
		if (msgstats) {
			msgstats->allocmsgs--;
		}
		if (msg->names) {
			for (j=0; j < msg->nfields; ++j) {
				if (msg->names[j]) {
					ha_free(msg->names[j]);
					msg->names[j] = NULL;
				}
			}
			ha_free(msg->names);
			msg->names = NULL;
		}
		if (msg->values) {
			for (j=0; j < msg->nfields; ++j) {
				if (msg->values[j] && msg->types[j]
				!=	FT_STRUCT) {
					ha_free(msg->values[j]);
					msg->values[j] = NULL;
				}else{
					ha_msg_del((struct ha_msg*)msg->values[j]);
					msg->values[j] = NULL;
				}
			}
			ha_free(msg->values);
			msg->values = NULL;
		}
		if (msg->nlens) {
			ha_free(msg->nlens);
			msg->nlens = NULL;
		}
		if (msg->vlens) {
			ha_free(msg->vlens);
			msg->vlens = NULL;
		}
		if (msg->types){
			ha_free(msg->types);
			msg->types = NULL;
		}
		msg->nfields = -1;
		msg->nalloc = -1;
		msg->stringlen = -1;
		msg->netstringlen = -1;
		ha_free(msg);
	}
}
struct ha_msg*
ha_msg_copy(const struct ha_msg *msg)
{
	struct ha_msg*		ret;
	int			j;


	AUDITMSG(msg);
	ret = MALLOCT(struct ha_msg);
	ret->nfields	= msg->nfields;
	ret->nalloc	= msg->nalloc;
	ret->stringlen	= msg->stringlen;
	ret->netstringlen = msg->netstringlen;

	ret->names  = (char **)	ha_calloc(sizeof(char *), msg->nalloc);
	ret->nlens  = (int *)	ha_calloc(sizeof(int), msg->nalloc);
	ret->values = (void **)	ha_calloc(sizeof(void *), msg->nalloc);
	ret->vlens  = (size_t *)	ha_calloc(sizeof(size_t), msg->nalloc);
	ret->types  = (int *) ha_calloc(sizeof(int), msg->nalloc);
	if (ret->names == NULL || ret->values == NULL
	||	ret->nlens == NULL || ret->vlens == NULL || ret->types == NULL) {
		cl_log(LOG_ERR
		,	"ha_msg_new: out of memory for ha_msg_copy");
		goto freeandleave;
	}
	memcpy(ret->nlens, msg->nlens, sizeof(msg->nlens[0])*msg->nfields);
	memcpy(ret->vlens, msg->vlens, sizeof(msg->nlens[0])*msg->nfields);
	memcpy(ret->types, msg->types, sizeof(msg->types[0])*msg->nfields);

	for (j=0; j < msg->nfields; ++j) {

		if ((ret->names[j] = ha_malloc(msg->nlens[j]+1)) == NULL) {
			goto freeandleave;
		}
		memcpy(ret->names[j], msg->names[j], msg->nlens[j]+1);

		if (ret->types[j] == FT_STRUCT){
			if ((ret->values[j]
			=	(void*)ha_msg_copy((struct ha_msg*)msg->values[j]))
			==	NULL){

				cl_log(LOG_ERR
				, "ha_msg_copy(): copy child message failed");
				goto freeandleave;
			}
		}else if ((ret->values[j] = ha_malloc(msg->vlens[j]+1))==NULL){
			goto freeandleave;
		}else{
			memcpy(ret->values[j], msg->values[j], msg->vlens[j]+1);
		}

	}
	return ret;

freeandleave:
	ha_msg_del(ret);
	ret=NULL;
	return ret;
}

#ifdef DOAUDITS
void
ha_msg_audit(const struct ha_msg* msg)
{
	int	doabort = FALSE;
	int	j;

	if (!msg) {
		return;
	}
	if (!ha_is_allocated(msg)) {
		cl_log(LOG_CRIT, "Message @ 0x%x is not allocated"
		,	(unsigned) msg);
		abort();
	}
	if (msg->nfields < 0) {
		cl_log(LOG_CRIT, "Message @ 0x%x has negative fields (%d)"
		,	(unsigned) msg, msg->nfields);
		doabort = TRUE;
	}
	if (msg->nalloc < 0) {
		cl_log(LOG_CRIT, "Message @ 0x%x has negative nalloc (%d)"
		,	(unsigned) msg, msg->nalloc);
		doabort = TRUE;
	}
	if (msg->stringlen < 0) {
		cl_log(LOG_CRIT
		,	"Message @ 0x%x has negative stringlen (%d)"
		,	(unsigned) msg, msg->stringlen);
		doabort = TRUE;
	}
	if (msg->stringlen < 4 * msg->nfields) {
		cl_log(LOG_CRIT
		,	"Message @ 0x%x has too small stringlen (%d)"
		,	(unsigned) msg, msg->stringlen);
		doabort = TRUE;
	}
	if (!ha_is_allocated(msg->names)) {
		cl_log(LOG_CRIT
		,	"Message names @ 0x%x is not allocated"
		,	(unsigned) msg->names);
		doabort = TRUE;
	}
	if (!ha_is_allocated(msg->values)) {
		cl_log(LOG_CRIT
		,	"Message values @ 0x%x is not allocated"
		,	(unsigned) msg->values);
		doabort = TRUE;
	}
	if (!ha_is_allocated(msg->nlens)) {
		cl_log(LOG_CRIT
		,	"Message nlens @ 0x%x is not allocated"
		,	(unsigned) msg->nlens);
		doabort = TRUE;
	}
	if (!ha_is_allocated(msg->vlens)) {
		cl_log(LOG_CRIT
		,	"Message vlens @ 0x%x is not allocated"
		,	(unsigned) msg->vlens);
		doabort = TRUE;
	}
	if (doabort) {
		abort();
	}
	for (j=0; j < msg->nfields; ++j) {
		if (!ha_is_allocated(msg->names[j])) {
			cl_log(LOG_CRIT, "Message name[%d] @ 0x%x"
			" is not allocated."
			,	j, (unsigned) msg->names[j]);
		}
		if (!ha_is_allocated(msg->values[j])) {
			cl_log(LOG_CRIT, "Message value [%d] @ 0x%x"
			" is not allocated."
			,	j, (unsigned) msg->values[j]);
		}
	}
}
#endif

/* low level implementation for ha_msg_add

   the caller is responsible to allocate/free memories
   for @name and @value.

   @type could be FT_STRING, FT_BINARY, FT_STRUCT

   1. FT_STRING:
	In this case, this function could be called by heartbeat
   or by a client. If @name is a normal string, then @value is a normal
   string. Otherwise if @name is in format of (t), where type is an
   interget, then @value is base64 version of binary data (t == FT_BINARY)
   or converted string for a child message (t == FT_STRUCT).


   2. FT_BINARY
	@type equals to FT_BINARY implies it is called by a client
   to add a binary field to a message because heartbeat itself does not
   add any binary field.

   3. FT_STRUCT
	@type equals to FT_STRUCT implies it is called by a client
   to add a child message to this message because heartbeat itself does not
   add any child message.

*/

static int
ha_msg_addraw_ll(struct ha_msg * msg, char * name, size_t namelen,
		 void * value, size_t vallen, int type, int depth)
{

	int	next;
	size_t	startlen = sizeof(MSG_START)-1;
	size_t	startlen_netstring = sizeof(MSG_START_NETSTRING) -1 ;
	size_t	newstringlen;

	char	*cp_name;
	size_t	cp_namelen;
	size_t	cp_vallen;
	char	*cp_value;
	int	internal_type;

	if (!msg || msg->names == NULL || msg->values == NULL) {
		cl_log(LOG_ERR,	"ha_msg_addraw_ll: cannot add field to ha_msg");
		return(HA_FAIL);
	}

	if (msg->nfields >= msg->nalloc) {
		char **	names = msg->names;
		int  *	nlens = msg->nlens;
		void **	values = msg->values;
		size_t*	vlens = msg->vlens;
		int *	types = msg->types;

		int nalloc = msg->nalloc + MINFIELDS;
		msg->names = 	(char **)ha_calloc(sizeof(char *), nalloc);
		msg->nlens = 	(int *)ha_calloc(sizeof(int), nalloc);
		msg->values = 	(void **)ha_calloc(sizeof(void *), nalloc);
		msg->vlens = 	(size_t *)ha_calloc(sizeof(size_t), nalloc);
		msg->types= 	(int*)ha_calloc(sizeof(int), nalloc);

		if (msg->names == NULL || msg->values == NULL
		||	msg->nlens == NULL || msg->vlens == NULL
		||	msg->types == NULL) {

			cl_log(LOG_ERR, "%s"
			,	"ha_msg_addraw_ll: out of memory for ha_msg");
			ha_msg_del(msg);

			cl_log(LOG_ERR,
				"ha_msg_addraw_ll: cannot add field to ha_msg");
			return(HA_FAIL);
		}

		memcpy(msg->names, names, msg->nalloc*sizeof(char *));
		memcpy(msg->nlens, nlens, msg->nalloc*sizeof(int));
		memcpy(msg->values, values, msg->nalloc*sizeof(void *));
		memcpy(msg->vlens, vlens, msg->nalloc*sizeof(size_t));
		memcpy(msg->types, types, msg->nalloc*sizeof(int));

		ha_free(names);
		ha_free(nlens);
		ha_free(values);
		ha_free(vlens);
		ha_free(types);

		msg->nalloc = nalloc;
	}
	
	if (namelen >= startlen && strncmp(name, MSG_START, startlen) == 0) {
		cl_log(LOG_ERR, "ha_msg_addraw_ll: illegal field");
		return(HA_FAIL);
	}
	if (namelen >= startlen_netstring
	    && strncmp(name, MSG_START_NETSTRING, startlen_netstring == 0)){
		cl_log(LOG_ERR, "ha_msg_addraw_ll: illegal field");
	}

	if (name == NULL || value == NULL
	    ||	namelen <= 0 || vallen < 0) {
		cl_log(LOG_ERR, "ha_msg_addraw_ll: "
		       "cannot add name/value to ha_msg");
		return(HA_FAIL);
	}

	switch(type){

	case FT_BINARY:

		/* 3 == "(type)" and 2 == "=" + "\n" */
		newstringlen = msg->stringlen + (namelen + 3 + B64_stringlen(vallen)+2);

		cp_name = name;
		cp_namelen = namelen;
		cp_value = value;
		cp_vallen = vallen;

		break;
	case FT_STRUCT:

		/* 3 == "(type)" and 2 == "=" + "\n" */
		newstringlen = msg->stringlen + namelen + 3 +  2;

		next = msg->nfields;
		msg->names[next] = name;
		msg->nlens[next] = namelen;
		msg->values[next] = value;
		msg->vlens[next] = vallen;
		msg->stringlen = newstringlen;
		msg->netstringlen += 0;
		/*  intlen(namelen) + (namelen) + intlen(vallen) + vallen + 4 */
		msg->netstringlen += 0; /* 4 for type*/
		msg->types[next] = FT_STRUCT;

		msg->nfields++;

		return(HA_OK);

	/*case FT_STRING: */
	default: 
		newstringlen =  msg->stringlen + (namelen+vallen+2);

		internal_type = FT_STRING;
		if (name[0] == '('){

			if (name[2] != ')'){
				cl_log(LOG_ERR
				, "ha_msg_addraw_ll(): no closing parentheses");
				return(HA_FAIL);
			}
			sscanf(name + 1, "%d", &internal_type);

			if (internal_type ==  FT_STRING){
				cl_log(LOG_ERR
				,	"ha_msg_addraw_ll(): wrong type");
				return(HA_FAIL);
			}
		}


		if (internal_type == FT_BINARY){
			char	tmpbuf[MAXMSG];
			int	nlo = 3; /*name length overhead */

			cp_name = name;
			cp_namelen = namelen - nlo ;
			memmove(cp_name, name + nlo, namelen - nlo);
			cp_name[namelen - nlo] = EOS;

			memcpy(tmpbuf, value,vallen);
			cp_vallen = base64_to_binary(tmpbuf, vallen
			,	value, vallen);				
			cp_value = value;

		}else if (internal_type ==  FT_STRUCT ){
			struct ha_msg	*tmpmsg;
			int	nlo = 3; /*name length overhead */

			cp_name = name;
			cp_namelen = namelen - nlo ;
			memmove(cp_name, name + nlo, namelen - nlo);
			cp_name[namelen - nlo] = EOS;

			if (convert(value, vallen, depth,SYM_TO_NL) != HA_OK){
				cl_log(LOG_ERR
				,	"ha_msg_addraw_ll(): convert failed");
				return(HA_FAIL);
			}

			tmpmsg = string2msg_ll(value, vallen,depth + 1, 0);
			if (tmpmsg == NULL){
				cl_log(LOG_ERR
				,	"ha_msg_addraw_ll()"
				": string2msg_ll failed");
				return(HA_FAIL);
			}
			ha_free(value);
			cp_value = (void*) tmpmsg;
			cp_vallen = sizeof(struct ha_msg);

		}else{
			cp_name = name;
			cp_namelen = namelen;		
			cp_value = value;
			cp_vallen = vallen;

		}

	}

	if (newstringlen >= MAXMSG) {
		cl_log(LOG_ERR, "ha_msg_addraw_ll(): "
		       "cannot add name/value to ha_msg (value too big)");
		return(HA_FAIL);
	}


	next = msg->nfields;
	msg->values[next] = cp_value;
	msg->vlens[next] = cp_vallen;
	msg->names[next] = cp_name;
	msg->nlens[next] = cp_namelen;
	msg->stringlen = newstringlen;

	msg->netstringlen += intlen(cp_namelen) + (cp_namelen)
	+	intlen(cp_vallen) + cp_vallen + 4 ;
	msg->netstringlen += 4; /* for type*/

	if (type == FT_BINARY || internal_type == FT_BINARY){
		msg->types[next] = FT_BINARY;
	}else if (internal_type == FT_STRUCT){
		msg->types[next] = FT_STRUCT;

	}


	msg->nfields++;
	AUDITMSG(msg);

	return(HA_OK);


}

static int
ha_msg_addraw(struct ha_msg * msg, const char * name, size_t namelen,
	      const void * value, size_t vallen, int type, int depth)
{

	char	*cpvalue;
	char	*cpname;
	int	ret;

	if ((cpname = ha_malloc(namelen+1)) == NULL) {
		cl_log(LOG_ERR, "ha_msg_addraw: no memory for string (name)");
		return(HA_FAIL);
	}
	strncpy(cpname, name, namelen);
	cpname[namelen] = EOS;

	if(type == FT_STRING || type == FT_BINARY){
		if ((cpvalue = ha_malloc(vallen+1)) == NULL) {
			cl_log(LOG_ERR, "ha_msg_addraw: no memory for string (value)");
			return(HA_FAIL);
		}
		memcpy(cpvalue, value, vallen);
		cpvalue[vallen] = EOS;	
	}else{
		cpvalue = (char*)ha_msg_copy( (const struct ha_msg*) value);
		if(cpvalue == NULL){
			cl_log(LOG_ERR, "ha_msg_addraw: copying message failed");
			ha_free(cpname);
			return(HA_FAIL);
		}
	}
	
	ret = ha_msg_addraw_ll(msg, cpname, namelen, cpvalue, vallen
	,	type, depth);

	if (ret != HA_OK){
		cl_log(LOG_ERR, "ha_msg_addraw(): ha_msg_addraw_ll failed");
		ha_free(cpname);
		ha_free(cpvalue);
	}

	return(ret);

}

/*Add a null-terminated name and binary value to a message*/
int
ha_msg_addbin(struct ha_msg * msg, const char * name,
	      const void * value, size_t vallen)
{

	return(ha_msg_addraw(msg, name, strlen(name),
			     value, vallen, FT_BINARY, 0));

}

/*Add a null-terminated name and struct value to a message*/
int
ha_msg_addstruct(struct ha_msg * msg, const char * name, void * value)
{
	
	/* size is 0 because size is useless in this case*/
	return ha_msg_addraw(msg, name, strlen(name), value, 0, FT_STRUCT, 0);
}


/* Add a null-terminated name and value to a message */
int
ha_msg_add(struct ha_msg * msg, const char * name, const char * value)
{
	return(ha_msg_nadd(msg, name, strlen(name), value, strlen(value)));
}

/* Add a name/value pair to a message (with sizes for name and value) */
int
ha_msg_nadd(struct ha_msg * msg, const char * name, int namelen
	    ,	const char * value, int vallen)
{
	return(ha_msg_addraw(msg, name, namelen, value, vallen, FT_STRING, 0));

}

/* Add a name/value/type to a message (with sizes for name and value) */
int
ha_msg_nadd_type(struct ha_msg * msg, const char * name, int namelen
	    ,	const char * value, int vallen, int type)
{
	return(ha_msg_addraw(msg, name, namelen, value, vallen, type, 0));

}



/* Add a "name=value" line to the name, value pairs in a message */
static int
ha_msg_add_nv_depth(struct ha_msg* msg, const char * nvline,
		    const char * bufmax, int depth)
{
	int		namelen;
	const char *	valp;
	int		vallen;

	if (!nvline) {
		cl_log(LOG_ERR, "ha_msg_add_nv: NULL nvline");
		return(HA_FAIL);
	}
	/* How many characters before the '='? */
	if ((namelen = strcspn(nvline, EQUAL)) <= 0
	||	nvline[namelen] != '=') {
		cl_log(LOG_WARNING, "ha_msg_add_nv: line doesn't contain '='");
		cl_log(LOG_INFO, "%s", nvline);
		return(HA_FAIL);
	}
	valp = nvline + namelen +1; /* Point just *past* the '=' */
	if (valp >= bufmax)		return HA_FAIL;
	vallen = strcspn(valp, CRNL);
	if ((valp + vallen) >= bufmax)	return HA_FAIL;

	/* Call ha_msg_nadd to actually add the name/value pair */
	return(ha_msg_addraw(msg, nvline, namelen, valp, vallen
	,	FT_STRING, depth));

}

int
ha_msg_add_nv(struct ha_msg* msg, const char * nvline,
	      const char * bufmax)
{

	return(ha_msg_add_nv_depth(msg, nvline, bufmax, 0));

}


static void *
cl_get_value(const struct ha_msg * msg, const char * name,
	     size_t * vallen, int *type)
{

	int	j;
	if (!msg || !msg->names || !msg->values) {
		cl_log(LOG_ERR, "ha_msg_value: NULL msg");
		return(NULL);
	}

	AUDITMSG(msg);
	for (j=0; j < msg->nfields; ++j) {
		if (strcmp(name, msg->names[j]) == 0) {
			if (vallen){
				*vallen = msg->vlens[j];
			}
			if (type){
				*type = msg->types[j];
			}
			return(msg->values[j]);
		}
	}
	return(NULL);
}


const void *
cl_get_binary(const struct ha_msg *msg,
	      const char * name, size_t * vallen)
{

	const void	*ret;
	int		type;

	ret = cl_get_value( msg, name, vallen, &type);
	
	if (ret == NULL){
		/*
		cl_log(LOG_WARNING, "field %s not found", name);
		cl_log_message(msg);
		*/
		return(NULL);
	}
	if ( type != FT_BINARY){
		cl_log(LOG_WARNING, "field %s is not binary", name);
		cl_log_message(msg);
		return(NULL);
	}

	return(ret);
}

const char *
cl_get_string(const struct ha_msg *msg, const char *name)
{

	const void	*ret;
	int		type;
	ret = cl_get_value( msg, name, NULL, &type);

	if (ret == NULL || type != FT_STRING){
		return(NULL);
	}

	return(ret);

}

int
cl_get_type(const struct ha_msg *msg, const char *name)
{

	const void	*ret;
	int		type;

	ret =  cl_get_value( msg, name, NULL, &type);

	if (ret == NULL) {
		return -1;
	}
	if (type != FT_STRING && type != FT_BINARY && type != FT_STRUCT) {
		cl_log(LOG_WARNING, "field %s not a valid type"
		,	name);
		return(-1);
	}

	return(type);

}

struct ha_msg *
cl_get_struct(const struct ha_msg *msg, const char* name)
{
	struct ha_msg	*ret;
	int		type;
	size_t		vallen;

	ret = (struct ha_msg *)cl_get_value(msg, name, &vallen, &type);

	if (ret == NULL || type != FT_STRUCT){
		return(NULL);
	}
	return(ret);
}


static int
cl_msg_mod(struct ha_msg * msg, const char * name,
	       const void* value, size_t vlen, int type)
{  
  	int j;
	
	AUDITMSG(msg);
	if (msg == NULL || name == NULL || value == NULL) {
		cl_log(LOG_ERR, "cl_msg_mod: NULL input.");
		return HA_FAIL;
	}
	for (j=0; j < msg->nfields; ++j) {
		if (strcmp(name, msg->names[j]) == 0) {
			
			char *	newv ;
			int	newlen = vlen;
			int	sizediff = 0;
			
			if (type != msg->types[j]){
				cl_log(LOG_ERR, "cl_msg_mod: "
				       "type mismatch for field %s", name);
				return(HA_FAIL);
			}
			
			if(type == FT_STRING || type == FT_BINARY){
				newv =  ha_malloc(vlen + 1);
				if (newv == NULL) {
					cl_log(LOG_ERR, "cl_msg_mod: out of memory");
					return(HA_FAIL);
				}
				
			
				memcpy(newv, value, vlen);
				newv[vlen] = '\0';			
				ha_free(msg->values[j]);
			} else{
				newv = (char*)ha_msg_copy( (const struct ha_msg*)value);
				if( newv == NULL){
					cl_log(LOG_ERR, "cl_msg_mod: make a message copy failed");
					return(HA_FAIL);
				}
				ha_msg_del((struct ha_msg *) msg->values[j]);
			}


			msg->values[j] = newv;
			sizediff = newlen - msg->vlens[j];
			msg->stringlen += sizediff;
			msg->netstringlen += intlen(newlen) + newlen
				-	intlen(msg->vlens[j]) - msg->vlens[j];
			
			msg->vlens[j] = newlen;
			AUDITMSG(msg);
			return(HA_OK);
		}
	}
	
	return(ha_msg_nadd_type(msg, name,strlen(name), value, vlen, type));
  
}

int
cl_msg_modstruct(struct ha_msg * msg, const char* name, 
		 const struct ha_msg* value)
{
	return cl_msg_mod(msg, name, value, 0, FT_STRUCT);	
}

int
cl_msg_modbin(struct ha_msg * msg, const char* name, 
	      const void* value, size_t vlen)
{
	return cl_msg_mod(msg, name, value, vlen, FT_BINARY);
	
}


/* Modify the value associated with a particular name */
int
cl_msg_modstring(struct ha_msg * msg, const char * name, const char * value)
{
	return cl_msg_mod(msg, name, value, strlen(value), FT_STRING);
}



/* Return the next message found in the stream */
struct ha_msg *
msgfromstream(FILE * f)
{
	char		buf[MAXMSGLINE];
	char *		getsret;
	clearerr(f);
	/* Skip until we find a MSG_START (hopefully we skip nothing) */
	while(1) {
		getsret = fgets(buf, sizeof(buf), f);
		if (!getsret) {
			break;
		}
		if (strcmp(buf, MSG_START) == 0) {
			return msgfromstream_string(f);

		}
		if (strcmp(buf, MSG_START_NETSTRING) == 0){
			return msgfromstream_netstring(f);
		}

	}

	return NULL;
}

/* Return the next message found in the stream with string format */
struct ha_msg *
msgfromstream_string(FILE * f)
{
	char		buf[MAXMSGLINE];
	const char *	bufmax = buf + sizeof(buf);
	struct ha_msg*	ret;
	char *		getsret;


	if ((ret = ha_msg_new(0)) == NULL) {
		/* Getting an error with EINTR is pretty normal */
		/* (so is EOF) */
		if (   (!ferror(f) || (errno != EINTR && errno != EAGAIN))
		&&	!feof(f)) {
			cl_log(LOG_ERR, "msgfromstream: cannot get message");
		}
		return(NULL);
	}

	/* Add Name=value pairs until we reach MSG_END or EOF */
	while(1) {
		getsret = fgets(buf, MAXMSGLINE, f);
		if (!getsret) {
			break;
		}

		if (strnlen(buf, MAXMSGLINE) > MAXMSGLINE - 2) {
			cl_log(LOG_DEBUG
			,	"msgfromstream: field too long [%s]"
			,	buf);
		}

		if (!strcmp(buf, MSG_END)) {
			break;
		}


		/* Add the "name=value" string on this line to the message */
		if (ha_msg_add_nv(ret, buf, bufmax) != HA_OK) {
			cl_log(LOG_ERR, "NV failure (msgfromsteam): [%s]"
			,	buf);
			ha_msg_del(ret); ret=NULL;
			return(NULL);
		}
	}
	return(ret);
}


/* Return the next message found in the stream with string format*/

struct ha_msg *
msgfromstream_netstring(FILE * f)
{
	struct ha_msg *		ret;
	char			total_databuf[MAXMSG];
	char *			sp = total_databuf;


	if ((ret = ha_msg_new(0)) == NULL) {
		/* Getting an error with EINTR is pretty normal */
		/* (so is EOF) */
		if (   (!ferror(f) || (errno != EINTR && errno != EAGAIN))
		&&	!feof(f)) {
			cl_log(LOG_ERR
			, "msgfromstream_netstring(): cannot get message");
		}
		return(NULL);
	}

	while(1) {
		int	namelen=-1;
		char *	name;
		char *	namebuf;
		int	datalen;
		char *	data;
		char *	databuf;
		int	n;
		int	typelen;
		char *  type;
		char *	typebuf;

		if (fscanf(f, "%d:", &namelen) <= 0 || namelen <= 0){
			cl_log(LOG_WARNING
			,	" msgfromstream_netstring()"
			": scanning for namelen failed");
			ha_msg_del(ret);
			return(NULL);
		}

		namebuf = ha_malloc(namelen + 2);

		if ((n = fread(namebuf, 1, namelen + 1, f)) != namelen + 1){
			cl_log(LOG_WARNING, "msgfromstream_netstring()"
			": Can't get enough name string,"
			"expecting %d bytes long name, got %d bytes"
			,	namelen, n);
			ha_msg_del(ret);
			return(NULL);
		}

		if (*(namebuf + namelen) != ',' ){
			cl_log(LOG_WARNING
			,	"msgfromstream_netstring()"
			": \",\" is missing in netstring for name");
			ha_msg_del(ret);
			return(NULL);
		}

		namebuf[namelen] = 0;
		name = namebuf;

		if (fscanf(f, "%d:", &typelen) <= 0 || typelen <= 0){

			if (!is_auth_netstring(total_databuf
			,	sp - total_databuf, name,namelen) ){
				cl_log(LOG_ERR
				,	"msgfromstream_netstring()"
				": netstring authentication"
				" failed msgfromstream_netstring()");
				cl_log_message(ret);
				ha_msg_del(ret);
				return(NULL);
			}

			return(ret);
		}

		typebuf = ha_malloc(typelen + 2);
		if ((n = fread(typebuf, 1, typelen + 1, f)) != typelen + 1){
			cl_log(LOG_WARNING
			,	"msgfromstream_netstring()"
			": Can't get enough type string,"
			"expecting %d bytes long type, got %d type"
			,	typelen, n);
			ha_msg_del(ret);
			return(NULL);
		}

		if (*(typebuf + typelen) != ',' ){
			cl_log(LOG_WARNING
			,	"msgfromstream_netstring()"
			": \",\" is missing in netstring for type");
			ha_msg_del(ret);
			return(NULL);
		}

		typebuf[typelen] = 0;
		type = typebuf;

		if (fscanf(f, "%d:", &datalen) <= 0) {
			cl_log(LOG_WARNING
			,	"msgfromstream_netstring()"
			": scanning for datalen failed");
			ha_msg_del(ret);
			return(NULL);
		}

		databuf = ha_malloc(datalen + 2);

		if ((n = fread(databuf, 1, datalen + 1, f)) != datalen + 1) {
			cl_log(LOG_WARNING
			,	"msgfromstream_netstring()"
			": Can't get enough data"
			", expecting %d bytes long data, got %d bytes"
			,	datalen, n);
			ha_msg_del(ret);
			return(NULL);
		}

		if (*(databuf + datalen ) != ',' ){
			cl_log(LOG_WARNING
			,	"msgfromstream_netstring()"
			": \",\" is missing in netstring for data");
			ha_msg_del(ret);
			return(NULL);
		}

		databuf[datalen] = 0;
		data = databuf ;

		sp += sprintf(sp, "%d:%s,", namelen, name);
		sp += sprintf(sp, "%d:%s,", typelen, type);
		sp += sprintf(sp, "%d:%s,", datalen, data);

		if (atoi(type) == FT_STRUCT){
			struct ha_msg	*tmpmsg;

			tmpmsg = netstring2msg(data, datalen, 1);
			data = (char*)tmpmsg;
			datalen = sizeof(struct ha_msg);
		}

		if (ha_msg_nadd_type(ret, name, namelen, data, datalen
		,	atoi(type)) != HA_OK){
			cl_log(LOG_WARNING
			,  "msgfromstream_netstring(): ha_msg_nadd_type fails");
			ha_msg_del(ret);
			return(NULL);
		}

		ha_free(namebuf);
		ha_free(databuf);
	}

}




/* Return the next message found in the IPC channel */
static struct ha_msg*
msgfromIPC_ll(IPC_Channel * ch, int need_auth)
{
	int		rc;
	IPC_Message*	ipcmsg;
	struct ha_msg*	hmsg;

	rc = ch->ops->waitin(ch);

	switch(rc) {
		default:
		case IPC_FAIL:
			cl_perror("msgfromIPC: waitin failure");
			return NULL;

		case IPC_BROKEN:
			sleep(1);
			return NULL;

		case IPC_INTR:
			return NULL;

		case IPC_OK:
			break;
	}


	ipcmsg = NULL;
	rc = ch->ops->recv(ch, &ipcmsg);
#if 0
	if (DEBUGPKTCONT) {
		cl_log(LOG_DEBUG, "msgfromIPC: recv returns %d ipcmsg = 0x%lx"
		,	rc, (unsigned long)ipcmsg);
	}
#endif
	if (rc != IPC_OK) {
		return NULL;
	}


	hmsg = wirefmt2msg_ll((char *)ipcmsg->msg_body, ipcmsg->msg_len, need_auth);
	if (ipcmsg->msg_done) {
		ipcmsg->msg_done(ipcmsg);
	}

	AUDITMSG(hmsg);
	return hmsg;
}



/* Return the next message found in the IPC channel */
struct ha_msg*
msgfromIPC(IPC_Channel * ch)
{
	return msgfromIPC_ll(ch, 1);
}


struct ha_msg*
msgfromIPC_noauth(IPC_Channel * ch)
{
	return msgfromIPC_ll(ch, 0);
}





/* Return the next message found in the IPC channel */
IPC_Message *
ipcmsgfromIPC(IPC_Channel * ch)
{
	int		rc;
	IPC_Message*	ipcmsg;

	rc = ch->ops->waitin(ch);

	switch(rc) {
		default:
		case IPC_FAIL:
			cl_perror("msgfromIPC: waitin failure");
			return NULL;

		case IPC_BROKEN:
			sleep(1);
			return NULL;

		case IPC_INTR:
			return NULL;

		case IPC_OK:
			break;
	}


	ipcmsg = NULL;
	rc = ch->ops->recv(ch, &ipcmsg);
#if 0
	if (DEBUGPKTCONT) {
		cl_log(LOG_DEBUG, "msgfromIPC: recv returns %d ipcmsg = 0x%lx"
		,	rc, (unsigned long)ipcmsg);
	}
#endif
	if (rc != IPC_OK) {
		return NULL;
	}


	return(ipcmsg);
}


/* Writes a message into a stream - used for serial lines */
int
msg2stream(struct ha_msg* m, FILE * f)
{
	size_t	len;
	char *	s  = msg2wirefmt(m, &len);

	if (s != NULL) {
		int	rc = HA_OK;
		if (fputs(s, f) == EOF) {
			rc = HA_FAIL;
			cl_perror("msg2stream: fputs failure");
		}
		if (fflush(f) == EOF) {
			cl_perror("msg2stream: fflush failure");
			rc = HA_FAIL;
		}
		ha_free(s);
		return(rc);
	}else{
		return(HA_FAIL);
	}
}
static void ipcmsg_done(IPC_Message* m);

static void
ipcmsg_done(IPC_Message* m)
{
	if (!m) {
		return;
	}
	if (m->msg_body) {
		ha_free(m->msg_body);
	}
	ha_free(m);
	m = NULL;
}


IPC_Message*
wirefmt2ipcmsg(void* p, size_t len, IPC_Channel* ch)
{
	IPC_Message*	ret = NULL;

	if (p == NULL){
	  return(NULL);
	}

	ret = MALLOCT(IPC_Message);
	if (!ret) {
		return(NULL);
	}
	ret->msg_done = ipcmsg_done;
	ret->msg_private = NULL;
	ret->msg_ch = ch;
	ret->msg_body = p;
	ret->msg_len = len;

	return ret;

}

IPC_Message*
hamsg2ipcmsg(struct ha_msg* m, IPC_Channel* ch)
{
	size_t		len;
	char *		s  = msg2wirefmt(m, &len);
	IPC_Message*	ret = NULL;



	if (s == NULL) {
		return ret;
	}
	ret = MALLOCT(IPC_Message);
	if (!ret) {
		ha_free(s);
		return ret;
	}
	ret->msg_done = ipcmsg_done;
	ret->msg_private = NULL;
	ret->msg_ch = ch;
	ret->msg_body = s;
	ret->msg_len = len;

	return ret;
}

struct ha_msg*
ipcmsg2hamsg(IPC_Message*m)
{
	struct ha_msg*	ret = NULL;


	ret = wirefmt2msg(m->msg_body, m->msg_len);
	return ret;
}

int
msg2ipcchan(struct ha_msg*m, IPC_Channel*ch)
{
	IPC_Message*	imsg;

	if (m == NULL || ch == NULL) {
		cl_log(LOG_ERR, "Invalid msg2ipcchan argument");
		errno = EINVAL;
		return HA_FAIL;
	}

	if ((imsg = hamsg2ipcmsg(m, ch)) == NULL) {
		cl_log(LOG_ERR, "hamsg2ipcmsg() failure");
		return HA_FAIL;
	}

	if (ch->ops->send(ch, imsg) != IPC_OK) {
		if (ch->ch_status == IPC_CONNECT) {
			cl_log(LOG_ERR
			,	"msg2ipcchan: ch->ops->send() failure");
		}
		imsg->msg_done(imsg);
		return HA_FAIL;
	}
	return HA_OK;
}

static gboolean (*msg_authentication_method)(const struct ha_msg* ret) = NULL;


void
cl_set_oldmsgauthfunc(gboolean (*authfunc)(const struct ha_msg*))
{
	msg_authentication_method = authfunc;
}


/* Converts a string (perhaps received via UDP) into a message */
static struct ha_msg *
string2msg_ll(const char * s, size_t length, int depth, int need_auth)
{
	struct ha_msg*	ret;
	int		startlen;
	int		endlen;
	const char *	sp = s;
	const char *	smax = s + length;


	if ((ret = ha_msg_new(0)) == NULL) {
		return(NULL);
	}

	startlen = sizeof(MSG_START)-1;
	if (strncmp(sp, MSG_START, startlen) != 0) {
		/* This can happen if the sender gets killed */
		/* at just the wrong time... */
		cl_log(LOG_WARNING, "string2msg_ll: no MSG_START");
		ha_msg_del(ret);
		return(NULL);
	}else{
		sp += startlen;
	}

	endlen = sizeof(MSG_END)-1;

	/* Add Name=value pairs until we reach MSG_END or end of string */

	while (*sp != EOS && strncmp(sp, MSG_END, endlen) != 0) {

		if (sp >= smax)		return(NULL);
		/* Skip over initial CR/NL things */
		sp += strspn(sp, CRNL);
		if (sp >= smax)		return(NULL);

		/* End of message marker? */
		if (strncmp(sp, MSG_END, endlen) == 0) {
			break;
		}
		/* Add the "name=value" string on this line to the message */
		if (ha_msg_add_nv_depth(ret, sp, smax, depth) != HA_OK) {
			cl_log(LOG_ERR, "NV failure (string2msg_ll):");
			cl_log(LOG_ERR, "Input string: [%s]", s);
			ha_msg_del(ret);
			return(NULL);
		}
		if (sp >= smax) {
			return(NULL);
		}
		sp += strcspn(sp, CRNL);
	}

	if (need_auth && msg_authentication_method
	&&		!msg_authentication_method(ret)) {
		const char* from = ha_msg_value(ret, F_ORIG);
		cl_log(LOG_WARNING
	       ,       "string2msg_ll: node [%s]"
	       " failed authentication", from ? from : "?");
		ha_msg_del(ret);
		ret = NULL;
	}
	return(ret);
}

struct ha_msg *
string2msg(const char * s, size_t length)
{
	return(string2msg_ll(s, length, 0, NEEDAUTH));
}


/* Converts a message into a string (for sending out UDP interface)

   used in two places:

   1.called by msg2string as a implementation for computing string for a
   message provided the buffer

   2.called by is_authentic. In this case, there are no start/end string
   and the "auth" field is not included in the string

   rules for generating a string:

   1) if the field is a string, then add "name=value" in the string followed by
   new line

   2) if the field is binary data, then add "(FT_BINARY)name=
   base64-version-of-binary-data" followed by a new line

   3) if the field is a child message, then add "(FT_STRUCT)name=
   converted-string-for-child-message" followed by a new line


*/


int
msg2string_buf(const struct ha_msg *m, char* buf, size_t len
,	int depth,int needhead)
{

	char *	bp = NULL;
	int	j;

	buf[0]=0;
	bp = buf;

	if (needhead){
		strcpy(bp, MSG_START);
		bp += strlen(MSG_START);
	}

	for (j=0; j < m->nfields; ++j) {

		if (needhead == NOHEAD && strcmp(m->names[j], F_AUTH) == 0) {
			continue;
		}

		if (m->types[j] == FT_BINARY || m->types[j] == FT_STRUCT){
			strcat(bp, "(");
			bp++;
			strcat(bp,FT_strings[m->types[j]]);
			bp++;
			strcat(bp,")");
			bp++;
		}

		strcat(bp, m->names[j]);
		bp += m->nlens[j];
		strcat(bp, "=");
		bp++;

		if (m->types[j] == FT_STRING ){

			strcat(bp, m->values[j]);
			bp += m->vlens[j];

		} else if (m->types[j] == FT_BINARY){
			int baselen;
			int truelen = 0;

			baselen = B64_stringlen(m->vlens[j]) + 1;
			truelen = binary_to_base64(m->values[j]
			,	m->vlens[j], bp, baselen);
			bp += truelen;
		} else{
			int	baselen = get_stringlen(
			(struct ha_msg*)	m->values[j], 0);

			if (msg2string_buf((struct ha_msg*)m->values[j]
			,	bp,baselen,depth + 1, NEEDHEAD) != HA_OK){

				cl_log(LOG_ERR
				, "msg2string_buf(): msg2string_buf for"
				" child message failed");

				return(HA_FAIL);

			}
			if (convert(bp, baselen, depth, NL_TO_SYM) != HA_OK){

				cl_log(LOG_ERR
				,	"msg2string_buf(): convert failed");

				return(HA_FAIL);

			}

			bp += strlen(bp);
		}

		strcat(bp,"\n");
		bp++;


	}
	if (needhead){
		strcat(bp, MSG_END);
		bp += strlen(MSG_END);
	}

	bp[0] = 0;

	if (bp > buf + len){

		cl_log(LOG_ERR, "msg2string_buf: out of memory bound"
		", bp=%p, buf + len=%p, len=%ld"
		,	bp, buf + len, (long)len);

		cl_log_message(m);

		return(HA_FAIL);

	}

	return(HA_OK);
}


char *
msg2string(const struct ha_msg *m)
{
	void	*buf;
	int	len;

	AUDITMSG(m);
	if (m->nfields <= 0) {
		cl_log(LOG_ERR, "msg2string: Message with zero fields");
		return(NULL);
	}

	len = get_stringlen(m, 0);

	buf = ha_malloc(len);


	if (buf == NULL) {
		cl_log(LOG_ERR, "msg2string: no memory for string");
		return(NULL);
	}else if (msg2string_buf(m, buf, len ,0, NEEDHEAD) != HA_OK){
		cl_log(LOG_ERR, "msg2string: msg2string_buf failed");
		ha_free(buf);
		return(NULL);
	}
	return(buf);
}


int
get_stringlen(const struct ha_msg *m, int depth)
{
	int	stringlen = m->stringlen;
	int	i;

	if (depth >= MAXDEPTH){
		cl_log(LOG_ERR, "get_stringlen(), MAXDEPTH exceeded");
		return(0);
	}
	for (i = 0; i < m->nfields; i++){
		if (m->types[i] == FT_STRUCT){
			int tmp;
			tmp = get_stringlen((struct ha_msg*)m->values[i]
			,	depth + 1);
			if (tmp == 0){
				cl_log(LOG_ERR, "get_stringlen(), 0 is returned");
				return(0);
			}
			stringlen += tmp;
		}

	}

	return(stringlen);
}

int
get_netstringlen(const struct ha_msg *m, int depth)
{

	int	netstringlen = m->netstringlen;
	int	i;

	if (depth >= MAXDEPTH){
		cl_log(LOG_ERR, "get_netstringlen(), MAXDEPTH exceeded");
		return(0);
	}
	for (i = 0; i < m->nfields; i++){
		if (m->types[i] == FT_STRUCT){
			int	tmp;
			int	namelen = m->nlens[i];

			tmp = get_netstringlen((struct ha_msg*)m->values[i]
			,	depth + 1);
			if (tmp <= 0){
				cl_log(LOG_ERR
				,	"get_stringlen(), %d is returned"
				,	tmp);
				return(0);
			}
			netstringlen += intlen(namelen) + namelen + 2;
						/* for name */
			netstringlen += 4;	/* for type */
			netstringlen += intlen(tmp) + tmp + 2;
						/* for child message */
		}

	}

	return(netstringlen);


}

char*
msg2wirefmt(const struct ha_msg*m, size_t* len)
{

	if (msgfmt == MSGFMT_NETSTRING) {
		return(msg2netstring(m, len));
	}
	else{
		char	*tmp;

		tmp = msg2string(m);
		/*
		*len = m->stringlen;
		cl_log(LOG_INFO, "m->stringlen =%d,strlen(tmp)=%d",
		m->stringlen, strlen(tmp));
		*/
		*len = strlen(tmp) + 1;
		return(tmp);
	}
}


static struct ha_msg*
wirefmt2msg_ll(const char* s, size_t length, int need_auth)
{

	int startlen;

	startlen = sizeof(MSG_START)-1;
	if (strncmp(s, MSG_START, startlen) == 0) {
		return(string2msg_ll(s, length, 0, need_auth));
	}

	startlen = sizeof(MSG_START_NETSTRING) - 1;
	if (strncmp(s, MSG_START_NETSTRING, startlen) == 0) {
		return netstring2msg(s, length, need_auth);
	}

	return NULL;

}




struct ha_msg*
wirefmt2msg(const char* s, size_t length)
{
	return(wirefmt2msg_ll(s, length, 1));
}


void
cl_log_message (const struct ha_msg *m)
{
	int	j;

	AUDITMSG(m);
	cl_log(LOG_INFO, "MSG: Dumping message with %d fields", m->nfields);

	for (j=0; j < m->nfields; ++j) {
		switch(m->types[j]){
		case(FT_BINARY):
		case(FT_STRUCT):
			cl_log(LOG_INFO, "MSG[%d] : [(%s)%s=%p]",j
			,	FT_strings[m->types[j]]
			,	m->names[j] ? m->names[j] : "NULL"
			,	m->values[j] ? m->values[j] : "NULL");

			if (m->types[j] == FT_STRUCT && m->values[j]){
				cl_log_message((struct ha_msg*)m->values[j]);
			}

			break;

		/* case(FT_STRING): */
		default: 
			cl_log(LOG_INFO, "MSG[%d] : [%s=%s]", j
		       ,	m->names[j] ? m->names[j] : "NULL"
		       ,	(const char*)(m->values[j] ? m->values[j] : "NULL"));

		}
	}
}


#ifdef TESTMAIN_MSGS
int
main(int argc, char ** argv)
{
	struct ha_msg*	m;
	while (!feof(stdin)) {
		if ((m=controlfifo2msg(stdin)) != NULL) {
			fprintf(stderr, "Got message!\n");
			if (msg2stream(m, stdout) == HA_OK) {
				fprintf(stderr, "Message output OK!\n");
			}else{
				fprintf(stderr, "Could not output Message!\n");
			}
		}else{
			fprintf(stderr, "Could not get message!\n");
		}
	}
	return(0);
}
#endif
/*
 * $Log: cl_msg.c,v $
 * Revision 1.19  2004/08/29 04:05:23  msoffen
 * Fixed end comment in previous log.
 *
 * Revision 1.18  2004/08/29 04:04:10  msoffen
 * Fixed end comment in previous log.
 *
 * Revision 1.17  2004/08/29 03:01:13  msoffen
 * Replaced all // COMMENTs with / * COMMENT * /
 *
 * Revision 1.16  2004/08/03 06:01:19  zhenh
 * fix a memory leak
 *
 * Revision 1.15  2004/07/15 09:17:38  zhenh
 * increase the size of ha_msg autmatically
 *
 * Revision 1.14  2004/07/07 19:07:15  gshi
 * implemented uuid as nodeid
 *
 * Revision 1.13  2004/06/24 20:54:35  gshi
 * add version 1.11 log that I overwritten in the last commit
 *
 * Revision 1.12  2004/06/24 20:49:49  gshi
 * remove commented code
 * Revision 1.11  2004/06/24 20:44:29  gshi
 * added cl_msg_modstring() cl_msg_modstruct() cl_msg_modbin()
 * they call call cl_msg_mod()
 *
 *
 * fixed a bug in cl_msg_addstruct() that will cause memory getting freed twice
 * if a parent and its child message is deleted. 
 * Revision 1.10  2004/06/18 03:04:33  alan
 * Changed a few checks for non-existent fields to return NULL
 * silently.  This is the right behavior (really!).
 *
 * Revision 1.9  2004/04/29 01:22:30  alan
 * Undid a broken fix to the %zd format string problem.
 * It was replaced with %xd which prints in hex instead of decimal, and also
 * inserts a d in the output string.
 *
 * Revision 1.8  2004/04/28 17:27:13  gshi
 * Fix potential (though probably unlikely) memory leak
 * similar to the one found in cl_netstring.c by kevin
 *
 * Revision 1.7  2004/04/21 14:33:56  msoffen
 * %z is not a standard formatting character.  Changed to a %x
 *
 * Revision 1.6  2004/04/17 13:45:13  alan
 * More FreeBSD/64-bit problems fixed.  Problems found by ward.viaene@student.khleuven.be.
 *
 * Revision 1.5  2004/04/17 07:54:50  alan
 * Fixed a number of 64-bit portability issues discovered by Ward Viaene in FreeBSD.
 *
 * Revision 1.4  2004/04/02 12:06:39  andrew
 * Link the size of the receive buffer/limit to that of the send buffer/limit
 *
 * Revision 1.3  2004/03/31 23:34:44  alan
 * Fixed a bug I introduced into the netstrings stuff - when I moved things
 * from the heartbeat directory to the lib directory
 *
 * Revision 1.2  2004/03/25 08:05:23  alan
 * Moved libraries from heartbeat to lib directory
 * also fixed numerous signed/unsigned problems...
 *
 * Revision 1.1  2004/03/24 17:04:08  alan
 * Moved ha_msg.c and netstring.c to the lib/clplumbing directory.
 *
 * Revision 1.52  2004/03/10 22:52:46  andrew
 * Allow people to distinguish between this error and one further up.
 *
 * Revision 1.51  2004/03/05 17:25:18  alan
 * cleanup of netstring patch.
 * Hopefully it also cleaned up the size_t vs int problems in the code.
 *
 * Revision 1.50  2004/03/03 05:31:50  alan
 * Put in Gochun Shi's new netstrings on-the-wire data format code.
 * this allows sending binary data, among many other things!
 *
 * Revision 1.49  2004/02/17 22:11:57  lars
 * Pet peeve removal: _Id et al now gone, replaced with consistent Id header.
 *
 * Revision 1.48  2004/01/21 11:34:14  horms
 * - Replaced numerous malloc + strcpy/strncpy invocations with strdup
 *   * This usually makes the code a bit cleaner
 *   * Also is easier not to make code with potential buffer over-runs
 * - Added STRDUP to pils modules
 * - Removed some spurious MALLOC and FREE redefinitions
 *   _that could never be used_
 * - Make sure the return value of strdup is honoured in error conditions
 *
 * Revision 1.47  2003/11/10 08:55:20  lars
 * Bugfixes by Deng, Pan:
 *
 * - While receiving a ha_msg, the default number of fields is MINFIELDS,
 *   which is 20. After the reception, if more than 20 fields needed to be
 *   added, it will fail.  I changed the MINFIELDS to 30. It is not a
 *   graceful fix, but it can work for checkpoint service. I think the max
 *   fields should not be fixed.
 *
 * - The message create routine ha_msg_new() in ha_msg.c. It takes a
 *   parameter nfields, but the function does not use it at all. If nfields
 *   > MINFIELDS, the allocated fields should be nfields.
 *
 * Revision 1.46  2003/10/29 04:05:00  alan
 * Changed things so that the API uses IPC instead of FIFOs.
 * This isn't 100% done - python API code needs updating, and need to check authorization
 * for the ability to "sniff" other people's packets.
 *
 * Revision 1.45  2003/07/14 04:30:49  alan
 * This patch from Kurosawa-san (by way of Horms):
 *    Heartbeat uses poll() in order to check messages in API FIFO and
 *    stdio functions to read messages.  stdio functions (fgets() in
 *    msgfromstream() in this case) uses a internal buffer.  When an application
 *    sends 2 messages at a time to API FIFO,  heartbeat's fgets() in
 *    msgfromstream() may read 2 messages to the internal buffer at a time.
 *    But heartbeat processes only one message and leaves the latter
 *    message, because there is no poll() event for the file descriptor.
 *
 * Revision 1.44  2003/06/24 06:36:51  alan
 * Fixed an unsafe sprintf which occurred only when high levels of debug
 * were turned on.
 *
 * Revision 1.43  2003/05/09 15:15:37  alan
 * Turned off the most expensive and onerous debugging code.
 *
 * Revision 1.42  2003/04/18 06:33:54  alan
 * Changed the audit code for messages to tolerate NULL message pointers.
 *
 * Revision 1.41  2003/04/18 06:09:46  alan
 * Fixed an off-by-one error in writing messages to the FIFO.
 * Also got rid of some now-unused functions, and fixed a minor glitch in BasicSanitCheck.
 *
 * Revision 1.40  2003/04/15 23:05:01  alan
 * Added new message copying function, and code
 * to check the integrity of messages.  Too slow now, will turn it down later.
 *
 * Revision 1.39  2003/03/27 07:04:26  alan
 * 1st step in heartbeat process restructuring.
 * Create fifo_child() processes to read the FIFO written by the shell scripts.
 *
 * Revision 1.38  2003/02/07 08:37:16  horms
 * Removed inclusion of portability.h from .h files
 * so that it does not need to be installed.
 *
 * Revision 1.37  2003/02/05 09:06:33  horms
 * Lars put a lot of work into making sure that portability.h
 * is included first, everywhere. However this broke a few
 * things when building against heartbeat headers that
 * have been installed (usually somewhere under /usr/include or
 * /usr/local/include).
 *
 * This patch should resolve this problem without undoing all of
 * Lars's hard work.
 *
 * As an asside: I think that portability.h is a virus that has
 * infected all of heartbeat's code and now must also infect all
 * code that builds against heartbeat. I wish that it didn't need
 * to be included all over the place. Especially in headers to
 * be installed on the system. However, I respect Lars's opinion
 * that this is the best way to resolve some weird build problems
 * in the current tree.
 *
 * Revision 1.36  2002/11/22 07:04:39  horms
 * make lots of symbols static
 *
 * Revision 1.35  2002/10/30 17:17:40  alan
 * Added some debugging, and changed one message from an ERROR to a WARNING.
 *
 * Revision 1.34  2002/10/22 17:41:58  alan
 * Added some documentation about deadtime, etc.
 * Switched one of the sets of FIFOs to IPC channels.
 * Added msg_from_IPC to ha_msg.c make that easier.
 * Fixed a few compile errors that were introduced earlier.
 * Moved hb_api_core.h out of the global include directory,
 * and back into a local directory.  I also make sure it doesn't get
 * installed.  This *shouldn't* cause problems.
 * Added a ipc_waitin() function to the IPC code to allow you to wait for
 * input synchronously if you really want to.
 * Changes the STONITH test to default to enabled.
 *
 * Revision 1.33  2002/10/21 10:17:18  horms
 * hb api clients may now be built outside of the heartbeat tree
 *
 * Revision 1.32  2002/10/18 07:16:08  alan
 * Put in Horms big patch plus a patch for the apcmastersnmp code where
 * a macro named MIN returned the MAX instead.  The code actually wanted
 * the MAX, so when the #define for MIN was surrounded by a #ifndef, then
 * it no longer worked...  This fix courtesy of Martin Bene.
 * There was also a missing #include needed on older Linux systems.
 *
 * Revision 1.31  2002/10/08 14:33:18  msoffen
 * Changed cl_log_message to be NULL safe.
 *
 * Revision 1.30  2002/10/02 13:36:42  alan
 * Put in a fix from Nathan Wallwork for a potential security vulnerability.
 *
 * Revision 1.29  2002/09/26 06:09:38  horms
 * log a debug message if it looks like an feild in a heartbeat message has been truncated
 *
 * Revision 1.28  2002/09/20 02:09:50  alan
 * Switched heartbeat to do everything with longclock_t instead of clock_t.
 * Switched heartbeat to be configured fundamentally from millisecond times.
 * Changed heartbeat to not use alarms for much of anything.
 * These are relatively major changes, but the seem to work fine.
 *
 * Revision 1.27  2002/09/17 20:48:06  alan
 * Put in a check for NULL in ha_msg_mod().
 *
 * Revision 1.26  2002/08/10 02:13:32  alan
 * Better error logging when ha_msg functions are given bad name/value pairs.
 *
 * Revision 1.25  2002/07/08 04:14:12  alan
 * Updated comments in the front of various files.
 * Removed Matt's Solaris fix (which seems to be illegal on Linux).
 *
 * Revision 1.24  2002/04/13 22:35:08  alan
 * Changed ha_msg_add_nv to take an end pointer to make it safer.
 * Added a length parameter to string2msg so it would be safer.
 * Changed the various networking plugins to use the new string2msg().
 *
 * Revision 1.23  2002/04/11 05:57:44  alan
 * Made some of the debugging output clearer.
 *
 * Revision 1.22  2002/02/21 21:43:33  alan
 * Put in a few fixes to make the client API work more reliably.
 * Put in a few changes to the process exit handling code which
 * also cause heartbeat to (attempt to) restart when it finds one of it's
 * own processes dies.  Restarting was already broken :-(
 *
 * Revision 1.21  2002/02/14 14:09:29  alan
 * Put in a change requested by Ram Pai to allow message values to be
 * empty strings.
 *
 * Revision 1.20  2001/10/24 20:46:28  alan
 * A large number of patches.  They are in these categories:
 *	Fixes from Matt Soffen
 *	Fixes to test environment things - including changing some ERRORs to
 *		WARNings and vice versa.
 *	etc.
 *
 * Revision 1.19  2001/08/21 15:37:13  alan
 * Put in code to make sure the calls in msg2stream get checked for errors...
 *
 * Revision 1.18  2001/06/19 13:56:28  alan
 * FreeBSD portability patch from Matt Soffen.
 * Mainly added #include "portability.h" to lots of files.
 * Also added a library to Makefile.am
 *
 * Revision 1.17  2001/06/12 17:05:47  alan
 * Fixed bug reported by Emily Ratliff <ratliff@austin.ibm.com>
 * In ha_msg_mod() the code fails to update the stringlen value for
 * fields modified by the input parameters.
 * This could potentially cause a crash.
 * Thanks to Emily for reporting this bug!
 *
 * Revision 1.16  2001/05/11 14:55:06  alan
 * Followed David Lee's suggestion about splitting out all the heartbeat process
 * management stuff into a separate header file...
 * Also changed to using PATH_MAX for maximum pathname length.
 *
 * Revision 1.15  2000/07/26 05:17:19  alan
 * Added GPL license statements to all the code.
 *
 * Revision 1.14  2000/07/19 23:03:53  alan
 * Working version of most of the API code.  It still has the security bug...
 *
 * Revision 1.13  2000/07/11 14:42:42  alan
 * More progress on API code.
 *
 * Revision 1.12  2000/07/11 00:25:52  alan
 * Added a little more API code.  It looks like the rudiments are now working.
 *
 * Revision 1.11  2000/05/11 22:47:50  alan
 * Minor changes, plus code to put in hooks for the new API.
 *
 * Revision 1.10  2000/04/12 23:03:49  marcelo
 * Added per-link status instead per-host status. Now we will able
 * to develop link<->service dependacy scheme.
 *
 * Revision 1.9  1999/11/22 20:28:23  alan
 * First pass of putting real packet retransmission.
 * Still need to request missing packets from time to time
 * in case retransmit requests get lost.
 *
 * Revision 1.8  1999/10/25 15:35:03  alan
 * Added code to move a little ways along the path to having error recovery
 * in the heartbeat protocol.
 * Changed the code for serial.c and ppp-udp.c so that they reauthenticate
 * packets they change the ttl on (before forwarding them).
 *
 * Revision 1.7  1999/10/10 20:11:56  alanr
 * New malloc/free (untested)
 *
 * Revision 1.6  1999/10/05 06:00:55  alanr
 * Added RPM Cflags to Makefiles
 *
 * Revision 1.5  1999/10/03 03:13:43  alanr
 * Moved resource acquisition to 'heartbeat', also no longer attempt to make the FIFO, it's now done in heartbeat.  It should now be possible to start it up more readily...
 *
 * Revision 1.4  1999/09/29 03:22:05  alanr
 * Added the ability to reread auth config file on SIGHUP
 *
 * Revision 1.3  1999/09/26 21:59:58  alanr
 * Allow multiple auth strings in auth file... (I hope?)
 *
 * Revision 1.2  1999/09/26 14:01:01  alanr
 * Added Mijta's code for authentication and Guenther Thomsen's code for serial locking and syslog reform
 *
 * Revision 1.9  1999/09/16 05:50:20  alanr
 * Getting ready for 0.4.3...
 *
 * Revision 1.8  1999/08/25 06:34:26  alanr
 * Added code to log outgoing messages in a FIFO...
 *
 * Revision 1.7  1999/08/18 04:28:48  alanr
 * added function to dump a message to the log...
 *
 * Revision 1.6  1999/08/17 03:46:48  alanr
 * added log entry...
 *
 */
