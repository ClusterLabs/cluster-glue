/* $Id: cl_msg.c,v 1.94 2005/11/01 15:07:14 andrew Exp $ */
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
#include <glib.h>
#include <clplumbing/cl_uuid.h>
#include <compress.h>

#define		MAXMSGLINE	512
#define		MINFIELDS	30
#define		NEWLINE		"\n"


#define		NEEDAUTH	1
#define		NOAUTH		0
#define		MAX_INT_LEN 	64
#define		MAX_NAME_LEN 	255
#define		UUID_SLEN	64
#define		MAXCHILDMSGLEN  512

static int	compression_threshold = (2*1024);

static enum cl_msgfmt msgfmt = MSGFMT_NVPAIR;
int	cl_max_msg_size = (512*1024);
static	gboolean use_traditional_compression = TRUE;

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
#define DOAUDITS
#ifdef DOAUDITS

void ha_msg_audit(const struct ha_msg* msg);

#	define	AUDITMSG(msg)	ha_msg_audit(msg)
#else
#	define	AUDITMSG(msg)	/*nothing*/
#endif


static volatile hb_msg_stats_t*	msgstats = NULL;

gboolean cl_msg_quiet_fmterr = FALSE;

extern int		netstring_format;

static struct ha_msg* wirefmt2msg_ll(const char* s, size_t length, int need_auth);

struct ha_msg* string2msg_ll(const char * s, size_t length, int need_auth, int depth);

extern int struct_stringlen(size_t namlen, size_t vallen, const void* value);
extern int struct_netstringlen(size_t namlen, size_t vallen, const void* value);
extern int process_netstring_nvpair(struct ha_msg* m, const char* nvpair, int nvlen);
static char*	msg2wirefmt_ll(struct ha_msg*m, size_t* len, gboolean need_compress);


void
cl_set_traditional_compression(gboolean value)
{
	use_traditional_compression = value;
}

void
cl_set_compression_threshold(size_t threadhold)
{
	compression_threshold = threadhold;

}

void
cl_msg_setstats(volatile hb_msg_stats_t* stats)
{
	msgstats = stats;
}

static int msg_stats_fd = -1;

static int
cl_msg_stats_open(const char* filename)
{
	if (filename == NULL){
		cl_log(LOG_ERR, "%s: filename is NULL", __FUNCTION__);
		return -1;
	}
	
	return open(filename, O_WRONLY|O_CREAT|O_APPEND);

}

static int
cl_msg_stats_close(void)
{
	if (msg_stats_fd > 0){
		close(msg_stats_fd);
	}
	
	msg_stats_fd = -1;
	
	return HA_OK;
}

#define STATSFILE "/var/log/ha_msg_stats"
int
cl_msg_stats_add(longclock_t time, int size)
{
	char	buf[MAXLINE];
	int	len;

	if (msg_stats_fd < 0){
		msg_stats_fd = cl_msg_stats_open(STATSFILE);
		if (msg_stats_fd < 0){
			cl_log(LOG_ERR, "%s:opening file failed",
			       __FUNCTION__);
			return HA_FAIL;
		}
	}

	
	sprintf(buf, "%lld %d\n", (long long)time, size);
	len = strnlen(buf, MAXLINE);
	if (write(msg_stats_fd, buf, len) ==  len){
		cl_msg_stats_close();
		return HA_OK;
	}

	cl_msg_stats_close();
	
	return HA_FAIL;;
	
}


/* Set default messaging format */
void
cl_set_msg_format(enum cl_msgfmt mfmt)
{
	msgfmt = mfmt;
}

void
cl_dump_msgstats(void)
{
	if (msgstats){
		cl_log(LOG_INFO, "dumping msg stats: "
		       "allocmsgs=%lu",
		      msgstats->allocmsgs);
	}
	return;
}
void
list_cleanup(GList* list)
{
	size_t i;
	for (i = 0; i < g_list_length(list); i++){
		char* element = g_list_nth_data(list, i);
		if (element == NULL){
			cl_log(LOG_WARNING, "list_cleanup:"
			       "element is NULL");
			continue;
		}
		ha_free(element);
	}
	g_list_free(list);
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
		ret->nlens     = (size_t *)ha_calloc(sizeof(size_t), nalloc);
		ret->values    = (void **)ha_calloc(sizeof(void *), nalloc);
		ret->vlens     = (size_t *)ha_calloc(sizeof(size_t), nalloc);
		ret->types	= (int*)ha_calloc(sizeof(int), nalloc);

		if (ret->names == NULL || ret->values == NULL
		||	ret->nlens == NULL || ret->vlens == NULL
		||	ret->types == NULL) {

			cl_log(LOG_ERR, "%s"
			,	"ha_msg_new: out of memory for ha_msg");
			/* It is safe to give this to ha_msg_del() */
			/* at this point.  It's well-enough-formed */
			ha_msg_del(ret); /*violated property*/
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

				if (msg->values[j] == NULL){
					continue;
				}
				
				if(msg->types[j] < DIMOF(fieldtypefuncs)){					
					fieldtypefuncs[msg->types[j]].memfree(msg->values[j]);
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
		ha_free(msg);
	}
}
struct ha_msg*
ha_msg_copy(const struct ha_msg *msg)
{
	struct ha_msg*		ret;
	int			j;

	
	AUDITMSG(msg);
	if (msg == NULL || (ret = ha_msg_new(msg->nalloc)) == NULL) {   
		return NULL;   
	} 

	ret->nfields	= msg->nfields;

	memcpy(ret->nlens, msg->nlens, sizeof(msg->nlens[0])*msg->nfields);
	memcpy(ret->vlens, msg->vlens, sizeof(msg->vlens[0])*msg->nfields);
	memcpy(ret->types, msg->types, sizeof(msg->types[0])*msg->nfields);

	for (j=0; j < msg->nfields; ++j) {
		
		if ((ret->names[j] = ha_malloc(msg->nlens[j]+1)) == NULL) {
			goto freeandleave;
		}
		memcpy(ret->names[j], msg->names[j], msg->nlens[j]+1);
		
		
		if(msg->types[j] < DIMOF(fieldtypefuncs)){					
			ret->values[j] = fieldtypefuncs[msg->types[j]].dup(msg->values[j],
									   msg->vlens[j]);
			if (!ret->values[j]){
				cl_log(LOG_ERR,"duplicating the message field failed");
				goto freeandleave;
			}
		}
	}
	return ret;

freeandleave:
        /*   
	 * ha_msg_del nicely handles partially constructed ha_msgs
	 * so, there's not really a memory leak here at all, but BEAM   
	 * thinks there is.   
	 */   
	ha_msg_del(ret);/* memory leak */       ret=NULL; 
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
		cl_log(LOG_CRIT, "Message @ %p is not allocated"
		,	 msg);
		abort();
	}
	if (msg->nfields < 0) {
		cl_log(LOG_CRIT, "Message @ %p has negative fields (%d)"
		,	msg, msg->nfields);
		doabort = TRUE;
	}
	if (msg->nalloc < 0) {
		cl_log(LOG_CRIT, "Message @ %p has negative nalloc (%d)"
		,	msg, msg->nalloc);
		doabort = TRUE;
	}

	if (!ha_is_allocated(msg->names)) {
		cl_log(LOG_CRIT
		,	"Message names @ %p is not allocated"
		,	 msg->names);
		doabort = TRUE;
	}
	if (!ha_is_allocated(msg->values)) {
		cl_log(LOG_CRIT
		,	"Message values @ %p is not allocated"
		,	msg->values);
		doabort = TRUE;
	}
	if (!ha_is_allocated(msg->nlens)) {
		cl_log(LOG_CRIT
		,	"Message nlens @ %p is not allocated"
		,	msg->nlens);
		doabort = TRUE;
	}
	if (!ha_is_allocated(msg->vlens)) {
		cl_log(LOG_CRIT
		,	"Message vlens @ %p is not allocated"
		,	msg->vlens);
		doabort = TRUE;
	}
	if (doabort) {
		cl_log_message(LOG_INFO,msg);
		abort();
	}
	for (j=0; j < msg->nfields; ++j) {
		
		
		if (msg->types[j] == FT_STRING){
			if (msg->vlens[j] != strlen(msg->values[j])){
				cl_log(LOG_ERR, "stringlen does not match");
				cl_log_message(LOG_INFO,msg);
				abort();
			}
		}
		
		if (!ha_is_allocated(msg->names[j])) {
			cl_log(LOG_CRIT, "Message name[%d] @ 0x%p"
			       " is not allocated." ,	
			       j, msg->names[j]);
			abort();
		}
		if (msg->types[j]  != FT_LIST && !ha_is_allocated(msg->values[j])) {
			cl_log(LOG_CRIT, "Message value [%d] @ 0x%p"
			       " is not allocated.",  j, msg->values[j]);
			cl_log_message(LOG_INFO, msg);
			abort();
		}
	}
}
#endif



static int
ha_msg_expand(struct ha_msg* msg )
{	
	char **	names ;
	size_t  *nlens ;
	void **	values ;
	size_t*	vlens ;
	int *	types ;
	int	nalloc;
       
	if(!msg){
		cl_log(LOG_ERR, "ha_msg_expand:"
		       "input msg is null");
		return HA_FAIL;
	}

	names = msg->names;
	nlens = msg->nlens;
	values = msg->values;
	vlens = msg->vlens;
	types = msg->types;
	
	nalloc = msg->nalloc + MINFIELDS;
	msg->names = 	(char **)ha_calloc(sizeof(char *), nalloc);
	msg->nlens = 	(size_t *)ha_calloc(sizeof(size_t), nalloc);
	msg->values = 	(void **)ha_calloc(sizeof(void *), nalloc);
	msg->vlens = 	(size_t *)ha_calloc(sizeof(size_t), nalloc);
	msg->types= 	(int*)ha_calloc(sizeof(int), nalloc);
	
	if (msg->names == NULL || msg->values == NULL
	    ||	msg->nlens == NULL || msg->vlens == NULL
	    ||	msg->types == NULL) {
		
		cl_log(LOG_ERR, "%s"
		       ,	" out of memory for ha_msg");		
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
	
	return HA_OK;
}

int
cl_msg_remove_value(struct ha_msg* msg, const void* value)
{
	int j;
	
	if (msg == NULL || value == NULL){
		cl_log(LOG_ERR, "cl_msg_remove: invalid argument");
		return HA_FAIL;
	}
	
	for (j = 0; j < msg->nfields; ++j){
		if (value == msg->values[j]){
			break;			
		}
	}
	if (j == msg->nfields){		
		cl_log(LOG_ERR, "cl_msg_remove: field %p not found", value);
		return HA_FAIL;
	}
	return cl_msg_remove_offset(msg, j);
	
}


int
cl_msg_remove(struct ha_msg* msg, const char* name)
{
	int j;
	
	if (msg == NULL || name == NULL){
		cl_log(LOG_ERR, "cl_msg_remove: invalid argument");
		return HA_FAIL;
	}
	
	for (j = 0; j < msg->nfields; ++j){
		if (strcmp(name, msg->names[j]) == 0){
			break;			
		}
	}
	
	if (j == msg->nfields){		
		cl_log(LOG_ERR, "cl_msg_remove: field %s not found", name);
		return HA_FAIL;
	}
	return cl_msg_remove_offset(msg, j);
}

int
cl_msg_remove_offset(struct ha_msg* msg, int offset)
{
	int j = offset;
	int i;
	
	if (j == msg->nfields){		
		cl_log(LOG_ERR, "cl_msg_remove: field %d not found", j);
		return HA_FAIL;
	}
		
	ha_free(msg->names[j]);
	fieldtypefuncs[msg->types[j]].memfree(msg->values[j]);
	
	for (i= j + 1; i < msg->nfields ; i++){
		msg->names[i -1] = msg->names[i];
		msg->nlens[i -1] = msg->nlens[i];
		msg->values[i -1] = msg->values[i];
		msg->vlens[i-1] = msg->vlens[i];
		msg->types[i-1] = msg->types[i];
	}
	msg->nfields--;

	
	return HA_OK;
}



/* low level implementation for ha_msg_add
   the caller is responsible to allocate/free memories
   for @name and @value.

*/

static int
ha_msg_addraw_ll(struct ha_msg * msg, char * name, size_t namelen,
		 void * value, size_t vallen, int type, int depth)
{
	
	size_t	startlen = sizeof(MSG_START)-1;
	int	internal_type;
	

	int (*addfield) (struct ha_msg* msg, char* name, size_t namelen,
			 void* value, size_t vallen, int depth);
		
	if (!msg || msg->names == NULL || (msg->values == NULL) ) {
		cl_log(LOG_ERR,	"ha_msg_addraw_ll: cannot add field to ha_msg");
		return(HA_FAIL);
	}
	
	if (msg->nfields >= msg->nalloc) {
		if( ha_msg_expand(msg) != HA_OK){
			cl_log(LOG_ERR, "message expanding failed");
			return(HA_FAIL);
		}
		
	}
	
	if (namelen >= startlen && strncmp(name, MSG_START, startlen) == 0) {
		if(!cl_msg_quiet_fmterr) {
			cl_log(LOG_ERR, "ha_msg_addraw_ll: illegal field");
		}
		return(HA_FAIL);
	}

	if (name == NULL || (value == NULL)
	    ||	namelen <= 0 || vallen < 0) {
		cl_log(LOG_ERR, "ha_msg_addraw_ll: "
		       "cannot add name/value to ha_msg");
		return(HA_FAIL);
	}
	
	internal_type = type;
	
	HA_MSG_ASSERT(type < DIMOF(fieldtypefuncs));
	
	addfield =  fieldtypefuncs[type].addfield;
	if (!addfield || 
	    addfield(msg, name, namelen, value, vallen,depth) != HA_OK){
		cl_log(LOG_ERR, "ha_msg_addraw_ll: addfield failed");
		return(HA_FAIL);
	}
	
	AUDITMSG(msg);

	return(HA_OK);


}

static int
ha_msg_addraw(struct ha_msg * msg, const char * name, size_t namelen,
	      const void * value, size_t vallen, int type, int depth)
{

	char	*cpvalue = NULL;
	char	*cpname = NULL;
	int	ret;

	if ((cpname = ha_malloc(namelen+1)) == NULL) {
		cl_log(LOG_ERR, "ha_msg_addraw: no memory for string (name)");
		return(HA_FAIL);
	}
	strncpy(cpname, name, namelen);
	cpname[namelen] = EOS;
	
	HA_MSG_ASSERT(type < DIMOF(fieldtypefuncs));
	
	if (fieldtypefuncs[type].dup){
		cpvalue = fieldtypefuncs[type].dup(value, vallen);	
	}
	if (cpvalue == NULL){
		cl_log(LOG_ERR, "ha_msg_addraw: copying message failed");
		ha_free(cpname);
		return(HA_FAIL);
	}
	
	ret = ha_msg_addraw_ll(msg, cpname, namelen, cpvalue, vallen
	,	type, depth);

	if (ret != HA_OK){
		cl_log(LOG_ERR, "ha_msg_addraw(): ha_msg_addraw_ll failed");
		ha_free(cpname);
		fieldtypefuncs[type].memfree(cpvalue);
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

int 
ha_msg_adduuid(struct ha_msg* msg, const char *name, const cl_uuid_t* u)
{
	return(ha_msg_addraw(msg, name, strlen(name),
			     u, sizeof(cl_uuid_t), FT_BINARY, 0));
}

/*Add a null-terminated name and struct value to a message*/
int
ha_msg_addstruct(struct ha_msg * msg, const char * name, const void * value)
{
	const struct ha_msg* childmsg = (const struct ha_msg*) value;
	
	if (get_netstringlen(childmsg) > MAXCHILDMSGLEN
	    || get_stringlen(childmsg) > MAXCHILDMSGLEN) {
		cl_log(LOG_WARNING,
		       "%s: childmsg too big (name=%s, nslen=%d, len=%d)."
		       "   Use ha_msg_addstruct_compress() instead.",
		       __FUNCTION__, name, get_netstringlen(childmsg), 
		       get_stringlen(childmsg));
	}
	
	return ha_msg_addraw(msg, name, strlen(name), value, 
			     sizeof(struct ha_msg), FT_STRUCT, 0);
}

int
ha_msg_addstruct_compress(struct ha_msg * msg, const char * name, const void * value)
{
	
	if (use_traditional_compression){
		return ha_msg_addraw(msg, name, strlen(name), value, 
				     sizeof(struct ha_msg), FT_STRUCT, 0);
	}else{
		return ha_msg_addraw(msg, name, strlen(name), value, 
				     sizeof(struct ha_msg), FT_UNCOMPRESS, 0);
	}
}

int
ha_msg_add_int(struct ha_msg * msg, const char * name, int value)
{
	char buf[MAX_INT_LEN];
	snprintf(buf, MAX_INT_LEN, "%d", value);
	return (ha_msg_add(msg, name, buf));	
}

int
ha_msg_mod_int(struct ha_msg * msg, const char * name, int value)
{
	char buf[MAX_INT_LEN];
	snprintf(buf, MAX_INT_LEN, "%d", value);
	return (cl_msg_modstring(msg, name, buf));	
}

int
ha_msg_value_int(const struct ha_msg * msg, const char * name, int* value)
{
	const char* svalue = ha_msg_value(msg, name);
	if(NULL == svalue) {
		return HA_FAIL;
	}
	*value = atoi(svalue);
	return HA_OK;
}

/*
 * ha_msg_value_str_list()/ha_msg_add_str_list():
 * transform a string list suitable for putting into an ha_msg is by a convention
 * of naming the fields into the following format:
 *	listname1=foo
 *	listname2=bar
 *	listname3=stuff
 *	etc.
 */

GList* 
ha_msg_value_str_list(struct ha_msg * msg, const char * name)
{
	
	int i = 1;
	int len = 0;
	const char* value;
	char* element;
	GList* list = NULL;
	
	
	if( NULL==msg||NULL==name||strnlen(name, MAX_NAME_LEN)>=MAX_NAME_LEN ){
		return NULL;
	}	
	len = cl_msg_list_length(msg,name);
	for(i=0; i<len; i++) {
		value = cl_msg_list_nth_data(msg,name,i);
		if (NULL == value) {
			break;
		}
		element = g_strdup(value);
		list = g_list_append(list, element);
	}
	return list;
}



static void
pair_to_msg(gpointer key, gpointer value, gpointer user_data)
{
	struct ha_msg* msg = (struct ha_msg*)user_data;
	if( HA_OK != ha_msg_add(msg, key, value)) {
		cl_log(LOG_ERR, "ha_msg_add in pair_to_msg failed");
	}
}


static struct ha_msg*
str_table_to_msg(GHashTable* hash_table)
{
	struct ha_msg* hash_msg;

	if ( NULL == hash_table) {
		return NULL;
	}

	hash_msg = ha_msg_new(5);
	g_hash_table_foreach(hash_table, pair_to_msg, hash_msg);
	return hash_msg;
}


static GHashTable*
msg_to_str_table(struct ha_msg * msg)
{
	int i;
	GHashTable* hash_table;

	if ( NULL == msg) {
		return NULL;
	}

	hash_table = g_hash_table_new(g_str_hash, g_str_equal);

	for (i = 0; i < msg->nfields; i++) {
		if( FT_STRING != msg->types[i] ) {
			continue;
		}
		g_hash_table_insert(hash_table,
				    g_strndup(msg->names[i],msg->nlens[i]),
				    g_strndup(msg->values[i],msg->vlens[i]));
	}
	return hash_table;
}

GHashTable*
ha_msg_value_str_table(struct ha_msg * msg, const char * name)
{
	struct ha_msg* hash_msg;
	GHashTable * hash_table = NULL;

	if (NULL == msg || NULL == name) {
		return NULL;
	}

	hash_msg = cl_get_struct(msg, name);
	if (NULL == hash_msg) {
		return NULL;
	}
	hash_table = msg_to_str_table(hash_msg);
	return hash_table;
}

int
ha_msg_add_str_table(struct ha_msg * msg, const char * name,
			GHashTable* hash_table)
{
	struct ha_msg* hash_msg;
	if (NULL == msg || NULL == name || NULL == hash_table) {
		return HA_FAIL;
	}

	hash_msg = str_table_to_msg(hash_table);
	if( HA_OK != ha_msg_addstruct(msg, name, hash_msg)) {
		ha_msg_del(hash_msg);
		cl_log(LOG_ERR, "ha_msg_add in ha_msg_add_str_table failed");
		return HA_FAIL;
	}
	ha_msg_del(hash_msg);
	return HA_OK;
}






int
cl_msg_list_add_string(struct ha_msg* msg, const char* name, const char* value)
{
	GList* list = NULL;
	int ret;
	char buf[MAXMSG];
	
	if(!msg || !name || !value){
		cl_log(LOG_ERR, "cl_msg_list_add_string: input invalid");
		return HA_FAIL;
	}
	
	
	strncpy(buf, value, MAXMSG);
	list = g_list_append(list, buf);
	if (!list){
		cl_log(LOG_ERR, "cl_msg_list_add_string: append element to"
		       "a glist failed");
		return HA_FAIL;
	}
	
	ret = ha_msg_addraw(msg, name, strlen(name), list, 
			    string_list_pack_length(list),
			    FT_LIST, 0);
	
	g_list_free(list);
	
	return ret;

}

/* Add a null-terminated name and value to a message */
int
ha_msg_add(struct ha_msg * msg, const char * name, const char * value)
{
	if(name == NULL || value == NULL) {
		return HA_FAIL;
	}
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
		if (!cl_msg_quiet_fmterr) {
			cl_log(LOG_WARNING
			,	"ha_msg_add_nv_depth: line doesn't contain '='");
			cl_log(LOG_INFO, "%s", nvline);
		}
		return(HA_FAIL);
	}
	valp = nvline + namelen +1; /* Point just *past* the '=' */
	if (valp >= bufmax){
		return HA_FAIL;
	}
	vallen = strcspn(valp, NEWLINE);
	if ((valp + vallen) >= bufmax){
		return HA_FAIL;
	}

	if (vallen == 0){
		valp = NULL;
	}
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
		cl_log(LOG_ERR, "%s: wrong arugment",
		       __FUNCTION__);
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

static void *
cl_get_value_mutate(struct ha_msg * msg, const char * name,
	     size_t * vallen, int *type)
{
	
	int	j;
	if (!msg || !msg->names || !msg->values) {
		cl_log(LOG_ERR, "%s: wrong arugment",
		       __FUNCTION__);
		return(NULL);
	}
	
	AUDITMSG(msg);
	for (j=0; j < msg->nfields; ++j) {
		if (strcmp(name, msg->names[j]) == 0) {
			int tp = msg->types[j];
			if (fieldtypefuncs[tp].pregetaction){
				fieldtypefuncs[tp].pregetaction(msg, j);
			}
			
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
		cl_log_message(LOG_WARNING, msg);
		return(NULL);
	}

	return(ret);
}

/* UUIDs are stored with a machine-independent byte ordering (even though it's binary) */
int
cl_get_uuid(const struct ha_msg *msg, const char * name, cl_uuid_t* retval)
{
	const void *	vret;
	size_t		vretsize;
	
	cl_uuid_clear(retval);

	if ((vret = cl_get_binary(msg, name, &vretsize)/*discouraged function*/) == NULL) {
		/* But perfectly portable in this case */
		return HA_FAIL;
	}
	if (vretsize != sizeof(cl_uuid_t)) {
		cl_log(LOG_WARNING, "Binary field %s is not a uuid.", name);
		cl_log(LOG_INFO, "expecting %d bytes, got %d bytes",
		       (int)sizeof(cl_uuid_t), (int)vretsize);
		cl_log_message(LOG_INFO, msg);
		return HA_FAIL;
	}
	memcpy(retval, vret, sizeof(cl_uuid_t));
	return HA_OK;
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
	if (type < 0){
		cl_log(LOG_WARNING, "field %s not a valid type"
		       ,	name);
		return(-1);
	}

	return(type);

}

/*
struct ha_msg *
cl_get_struct(const struct ha_msg *msg, const char* name)
{
	struct ha_msg*	ret;
	int		type;
	size_t		vallen;

	ret = cl_get_value(msg, name, &vallen, &type);
	
	if (ret == NULL ){
		return(NULL);
	}
	
	switch(type){
		
	case FT_STRUCT:
		break;
		
	default:
		cl_log(LOG_ERR, "%s: field %s is not a struct (%d)",
		       __FUNCTION__, name, type);
		return NULL;
	}
	
	return ret;
}
*/


struct ha_msg *
cl_get_struct(struct ha_msg *msg, const char* name)
{
	struct ha_msg*	ret;
	int		type = -1;
	size_t		vallen;
	
	ret = cl_get_value_mutate(msg, name, &vallen, &type);
	
	if (ret == NULL ){
		return(NULL);
	}
	
	switch(type){
		
	case FT_UNCOMPRESS:
	case FT_STRUCT:
		break;
		
	default:
		cl_log(LOG_ERR, "%s: field %s is not a struct (%d)",
		       __FUNCTION__, name, type);
		return NULL;
	}
	
	return ret;
}


int
cl_msg_list_length(struct ha_msg* msg, const char* name)
{
	GList*   ret;
	int		type;
	
	ret = cl_get_value( msg, name, NULL, &type);
	
	if ( ret == NULL || type != FT_LIST){
		return -1;
	}

	return g_list_length(ret);
	
}


void* 
cl_msg_list_nth_data(struct ha_msg* msg, const char* name, int n)
{
	GList*   ret;
	int		type;
	
	ret = cl_get_value( msg, name, NULL, &type);
	
	if ( ret == NULL || type != FT_LIST){
		cl_log(LOG_WARNING, "field %s not found "
		       " or type mismatch", name);
		return NULL;
	}
	
	return g_list_nth_data(ret, n);
	
}

int
cl_msg_add_list(struct ha_msg* msg, const char* name, GList* list)
{
	int		ret;
	
	if(msg == NULL|| name ==NULL || list == NULL){
		cl_log(LOG_ERR, "cl_msg_add_list:"
		       "invalid arguments");
		return HA_FAIL;
	}
	
	ret = ha_msg_addraw(msg, name, strlen(name), list, 
			    string_list_pack_length(list),
			    FT_LIST, 0);
	
	return ret;
}

GList*
cl_msg_get_list(struct ha_msg* msg, const char* name)
{
	GList*		ret;
	int		type;
	
	ret = cl_get_value( msg, name, NULL, &type);
	
	if ( ret == NULL || type != FT_LIST){
		cl_log(LOG_WARNING, "field %s not found "
		       " or type mismatch", name);
		return NULL;
	}	
	
	return ret;
}


int
cl_msg_add_list_str(struct ha_msg* msg, const char* name,
		    char** buf, size_t n)
{		
	GList*		list = NULL;
	int		i;
	int		ret = HA_FAIL;
	
	if (n <= 0  || buf == NULL|| name ==NULL ||msg == NULL){
		cl_log(LOG_ERR, "%s:"
		       "invalid parameter(%s)", 
		       !n <= 0?"n is negative or zero": 
		       !buf?"buf is NULL":
		       !name?"name is NULL":
		       "msg is NULL",__FUNCTION__);
		return HA_FAIL;
	}
	
	for ( i = 0; i < n; i++){
		if (buf[i] == NULL){
			cl_log(LOG_ERR, "%s: %dth element in buf is null",
			       __FUNCTION__, i);
			goto free_and_out;
		}
		list = g_list_append(list, buf[i]);
		if (list == NULL){
			cl_log(LOG_ERR, "%s:adding integer to list failed",
			       __FUNCTION__);
			goto free_and_out;
		}
	}
	
	ret = ha_msg_addraw(msg, name, strlen(name), list, 
			    string_list_pack_length(list),
			    FT_LIST, 0);
	
 free_and_out:
	if (list){
		g_list_free(list);
		list = NULL;
	}
	return ret;
}

static void
list_element_free(gpointer data, gpointer userdata)
{
	if (data){
		g_free(data);
	}	
}

int
cl_msg_add_list_int(struct ha_msg* msg, const char* name,
		    int* buf, size_t n)
{
	
	GList*		list = NULL;
	size_t		i;
	int		ret = HA_FAIL;
	
	if (n <= 0  || buf == NULL|| name ==NULL ||msg == NULL){
		cl_log(LOG_ERR, "cl_msg_add_list_int:"
		       "invalid parameter(%s)", 
		       !n <= 0?"n is negative or zero": 
		       !buf?"buf is NULL":
		       !name?"name is NULL":
		       "msg is NULL");
		goto free_and_out;
	}
	
	for ( i = 0; i < n; i++){
		char intstr[MAX_INT_LEN];		
		sprintf(intstr,"%d", buf[i]);
		list = g_list_append(list, g_strdup(intstr));
		if (list == NULL){
			cl_log(LOG_ERR, "cl_msg_add_list_int:"
			       "adding integer to list failed");
			goto free_and_out;
		}
	}
	
	ret = ha_msg_addraw(msg, name, strlen(name), list, 
			    string_list_pack_length(list),
			    FT_LIST, 0);
 free_and_out:
	if (list){
		g_list_foreach(list,list_element_free , NULL);
		g_list_free(list);
		list = NULL;
	}

	return ret;
}
int
cl_msg_get_list_int(struct ha_msg* msg, const char* name,
		     int* buf, size_t* n)
{
	GList* list;
	size_t	len;
	int	i;
	GList* list_element;
	

	if (n == NULL || buf == NULL|| name ==NULL ||msg == NULL){
		cl_log(LOG_ERR, "cl_msg_get_list_int:"
		       "invalid parameter(%s)", 
		       !n?"n is NULL": 
		       !buf?"buf is NULL":
		       !name?"name is NULL":
		       "msg is NULL");
		return HA_FAIL;
	}
	
	list = cl_msg_get_list(msg, name);
	if (list == NULL){
		cl_log(LOG_ERR, "cl_msg_get_list_int:"
		       "list of integers %s not found", name);
		return HA_FAIL;
	}

	len = g_list_length(list);
	if (len > *n){
		cl_log(LOG_ERR, "cl_msg_get_list_int:"
		       "buffer too small: *n=%ld, required len=%ld",
		       (long)*n, (long)len);
		*n = len;
		return HA_FAIL;	
	}
	
	*n = len; 
	i = 0;
	list_element = g_list_first(list);
	while( list_element != NULL){
		char* intstr = list_element->data;
		if (intstr == NULL){
			cl_log(LOG_ERR, "cl_msg_get_list_int:"
			       "element data is NULL");
			return HA_FAIL;
		}		
		
		if (sscanf(intstr,"%d", &buf[i]) != 1){
			cl_log(LOG_ERR, "cl_msg_get_list_int:"
			       "element data is NULL");
			return HA_FAIL;
		}
		
		i++;
		list_element = g_list_next(list_element);
	}
	
	return HA_OK;
}

/*this function is for internal use only*/
int 
cl_msg_replace(struct ha_msg* msg, int index,
		const char* value, size_t vlen, int type)
{
	char *	newv ;
	int	newlen = vlen;
	int	oldtype;
	
	AUDITMSG(msg);
	if (msg == NULL || value == NULL) {
		cl_log(LOG_ERR, "%s: NULL input.", __FUNCTION__);
		return HA_FAIL;
	}
	
	if(type >= DIMOF(fieldtypefuncs)){
		cl_log(LOG_ERR, "%s:"
		       "invalid type(%d)",__FUNCTION__, type);
		return HA_FAIL;
	}
	
	if (index >= msg->nfields){
		cl_log(LOG_ERR, "%s: index(%d) out of range(%d)",
		       __FUNCTION__,index, msg->nfields);
		return HA_FAIL;
	}
	
	oldtype = msg->types[index];
	
	newv = fieldtypefuncs[type].dup(value,vlen);
	if (!newv){
		cl_log(LOG_ERR, "%s: duplicating message fields failed"
		       "value=%p, vlen=%d, msg->names[i]=%s", 
		       __FUNCTION__,value, (int)vlen, msg->names[index]);
		return HA_FAIL;
	}
	
	fieldtypefuncs[oldtype].memfree(msg->values[index]);
	
	msg->values[index] = newv;
	msg->vlens[index] = newlen;
	msg->types[index] = type;
	AUDITMSG(msg);
	return(HA_OK);
	
}


static int
cl_msg_mod(struct ha_msg * msg, const char * name,
	       const void* value, size_t vlen, int type)
{  
  	int j;
	int rc;	

	AUDITMSG(msg);
	if (msg == NULL || name == NULL || value == NULL) {
		cl_log(LOG_ERR, "cl_msg_mod: NULL input.");
		return HA_FAIL;
	}
	
	if(type >= DIMOF(fieldtypefuncs)){
		cl_log(LOG_ERR, "cl_msg_mod:"
		       "invalid type(%d)", type);
		return HA_FAIL;
	}

	for (j=0; j < msg->nfields; ++j) {
		if (strcmp(name, msg->names[j]) == 0) {
			
			char *	newv ;
			int	newlen = vlen;
			
			if (type != msg->types[j]){
				cl_log(LOG_ERR, "%s: type mismatch(%d %d)",
				       __FUNCTION__, type, msg->types[j]);
				return HA_FAIL;
			}
			
			newv = fieldtypefuncs[type].dup(value,vlen);
			if (!newv){
				cl_log(LOG_ERR, "duplicating message fields failed"
				       "value=%p, vlen=%d, msg->names[j]=%s", 
				       value, (int)vlen, msg->names[j]);
				return HA_FAIL;
			}
						
			fieldtypefuncs[type].memfree(msg->values[j]);
			msg->values[j] = newv;
			msg->vlens[j] = newlen;
			AUDITMSG(msg);
			return(HA_OK);
		}
	}
	
	rc = ha_msg_nadd_type(msg, name,strlen(name), value, vlen, type);
  
	AUDITMSG(msg);
	return rc;
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
int
cl_msg_moduuid(struct ha_msg * msg, const char* name, 
	       const cl_uuid_t* uuid)
{
	return cl_msg_mod(msg, name, uuid, sizeof(cl_uuid_t), FT_BINARY);
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


/* Return the next message found in the stream with netstring format*/

struct ha_msg *
msgfromstream_netstring(FILE * f)
{
	struct ha_msg *		ret;

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
		char*	nvpair;
		int	nvlen;
		int	n;

		if (fscanf(f, "%d:", &nvlen) <= 0 || nvlen <= 0){
			return(ret);
		}

		nvpair = ha_malloc(nvlen + 2);
		
		if ((n =fread(nvpair, 1, nvlen + 1, f)) != nvlen + 1){
			cl_log(LOG_WARNING, "msgfromstream_netstring()"
			       ": Can't get enough nvpair,"
			       "expecting %d bytes long, got %d bytes",
			       nvlen + 1, n);
			ha_msg_del(ret);
			return(NULL);
		}
		
		process_netstring_nvpair(ret, nvpair, nvlen);

	}

}




/* Return the next message found in the IPC channel */
static struct ha_msg*
msgfromIPC_ll(IPC_Channel * ch, int flag)
{
	int		rc;
	IPC_Message*	ipcmsg;
	struct ha_msg*	hmsg;
	int		need_auth = flag & MSG_NEEDAUTH;
	int		allow_intr = flag & MSG_ALLOWINTR;
	
 startwait:
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
		if ( allow_intr){
			goto startwait;
		}else{
			return NULL;
		}
		
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
msgfromIPC(IPC_Channel * ch, int flag)
{
	return msgfromIPC_ll(ch, flag);
}


struct ha_msg*
msgfromIPC_noauth(IPC_Channel * ch)
{
	int flag = 0;
	
	flag |= MSG_ALLOWINTR;
	return msgfromIPC_ll(ch, flag);
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

static int clmsg_ipcmsg_allocated = 0;
static int clmsg_ipcmsg_freed = 0;

void dump_clmsg_ipcmsg_stats(void);
void
dump_clmsg_ipcmsg_stats(void)
{
	cl_log(LOG_INFO, "clmsg ipcmsg allocated=%d, freed=%d, diff=%d",
	       clmsg_ipcmsg_allocated,
	       clmsg_ipcmsg_freed,
	       clmsg_ipcmsg_allocated - clmsg_ipcmsg_freed);
	
	return;
}

static void
ipcmsg_done(IPC_Message* m)
{
	if (!m) {
		return;
	}
	if (m->msg_buf) {
		ha_free(m->msg_buf);
	}
	ha_free(m);
	m = NULL;
	clmsg_ipcmsg_freed ++;
}



/*
 * create an ipcmsg and copy the data
 */

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
	
	memset(ret, 0, sizeof(IPC_Message));
	
	if (NULL == (ret->msg_buf = cl_malloc(len + ch->msgpad))) {
		cl_free(ret);
		return NULL;
	}
	ret->msg_body = (char*)ret->msg_buf + ch->msgpad;
	memcpy(ret->msg_body, p, len);
	
	ret->msg_done = ipcmsg_done;
	ret->msg_private = NULL;
	ret->msg_ch = ch;
	ret->msg_len = len;

	clmsg_ipcmsg_allocated ++;

	return ret;

}

IPC_Message*
hamsg2ipcmsg(struct ha_msg* m, IPC_Channel* ch)
{
	size_t		len;
	char *		s  = msg2wirefmt_ll(m, &len, FALSE);
	IPC_Message*	ret = NULL;

	if (s == NULL) {
		return ret;
	}
	ret = MALLOCT(IPC_Message);
	if (!ret) {
		ha_free(s);
		return ret;
	}
	
	memset(ret, 0, sizeof(IPC_Message));

	if (NULL == (ret->msg_buf = cl_malloc(len + ch->msgpad))) {
		cl_free(s);
		cl_free(ret);
		return NULL;
	}
	ret->msg_body = (char*)ret->msg_buf + ch->msgpad;
	memcpy(ret->msg_body, s, len);
	cl_free(s);
	
	ret->msg_done = ipcmsg_done;
	ret->msg_private = NULL;
	ret->msg_ch = ch;
	ret->msg_len = len;

	clmsg_ipcmsg_allocated ++;

	return ret;
}

struct ha_msg*
ipcmsg2hamsg(IPC_Message*m)
{
	struct ha_msg*	ret = NULL;


	ret = wirefmt2msg(m->msg_body, m->msg_len,MSG_NEEDAUTH);
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
			snprintf(ch->failreason,MAXFAILREASON, 
				 "send failed,farside_pid=%d, sendq length=%ld(max is %ld)",
				 ch->farside_pid, (long)ch->send_queue->current_qlen, 
				 (long)ch->send_queue->max_qlen);	
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
struct ha_msg *
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
		if (!cl_msg_quiet_fmterr) {
			cl_log(LOG_WARNING, "string2msg_ll: no MSG_START");
		}
		ha_msg_del(ret);
		return(NULL);
	}else{
		sp += startlen;
	}

	endlen = sizeof(MSG_END)-1;

	/* Add Name=value pairs until we reach MSG_END or end of string */

	while (*sp != EOS && strncmp(sp, MSG_END, endlen) != 0) {

		if (sp >= smax)	{
			return(NULL);
		}
		/* Skip over initial CR/NL things */
		sp += strspn(sp, NEWLINE);
		if (sp >= smax)	{
			return(NULL);
		}
		/* End of message marker? */
		if (strncmp(sp, MSG_END, endlen) == 0) {
			break;
		}
		/* Add the "name=value" string on this line to the message */
		if (ha_msg_add_nv_depth(ret, sp, smax, depth) != HA_OK) {
			if (!cl_msg_quiet_fmterr) {
				cl_log(LOG_ERR, "NV failure (string2msg_ll):");
				cl_log(LOG_ERR, "Input string: [%s]", s);
				cl_log(LOG_ERR, "sp=%s", sp);
			}
			ha_msg_del(ret);
			return(NULL);
		}
		if (sp >= smax) {
			return(NULL);
		}
		sp += strcspn(sp, NEWLINE);
	}

	if (need_auth && msg_authentication_method
	&&		!msg_authentication_method(ret)) {
		const char* from = ha_msg_value(ret, F_ORIG);
		if (!cl_msg_quiet_fmterr) {
			cl_log(LOG_WARNING
		       ,       "string2msg_ll: node [%s]"
		       " failed authentication", from ? from : "?");
		}
		ha_msg_del(ret);
		ret = NULL;
	}
	return(ret);
}



struct ha_msg *
string2msg(const char * s, size_t length)
{
	return(string2msg_ll(s, length, 0, MSG_NEEDAUTH));
}






/* Converts a message into a string (for sending out UDP interface)
   
   used in two places:

   1.called by msg2string as a implementation for computing string for a
   message provided the buffer
   
   2.called by is_authentic. In this case, there are no start/end string
   and the "auth" field is not included in the string

*/

#define	NOROOM						{	\
		cl_log(LOG_ERR, "%s:%d: out of memory bound"	\
		", bp=%p, buf + len=%p, len=%ld"		\
		,	__FUNCTION__, __LINE__		\
		,	bp, buf + len, (long)len);		\
		cl_log_message(LOG_ERR, m);			\
		return(HA_FAIL);				\
	}

#define	CHECKROOM_CONST(c)		CHECKROOM_INT(STRLEN_CONST(c))
#define	CHECKROOM_STRING(s)		CHECKROOM_INT(strnlen(s, len))
#define	CHECKROOM_STRING_INT(s,i)	CHECKROOM_INT(strnlen(s, len)+(i))
#define	CHECKROOM_INT(i)	{		\
		if ((bp + (i)) > maxp) {	\
			NOROOM;			\
		}				\
	}


int
msg2string_buf(const struct ha_msg *m, char* buf, size_t len
,	int depth,int needhead)
{

	char *	bp = NULL;
	int	j;
	char* maxp = buf + len;

	buf[0]=0;
	bp = buf;

	if (needhead){
		CHECKROOM_CONST(MSG_START);
		strcpy(bp, MSG_START);
		bp += STRLEN_CONST(MSG_START);
	}

	for (j=0; j < m->nfields; ++j) {
		
		int truelen;
		int (*tostring)(char*, char*, void*, size_t, int);	

		if (needhead == NOHEAD && strcmp(m->names[j], F_AUTH) == 0) {
			continue;
		}

		if (m->types[j] != FT_STRING){
			CHECKROOM_STRING_INT(FT_strings[m->types[j]],2);
			strcat(bp, "(");
			bp++;
			strcat(bp, FT_strings[m->types[j]]);
			bp++;
			strcat(bp,")");
			bp++;
		}

		CHECKROOM_STRING_INT(m->names[j],1);
		strcat(bp, m->names[j]);
		bp += m->nlens[j];
		strcat(bp, "=");
		bp++;
		
		if(m->types[j] < DIMOF(fieldtypefuncs)){
			tostring = fieldtypefuncs[m->types[j]].tostring;
		} else {
			cl_log(LOG_ERR, "type(%d) unrecognized", m->types[j]);
			return HA_FAIL;
		}
		if (!tostring ||
		    (truelen = tostring(bp, maxp, m->values[j], m->vlens[j], depth))
		    < 0){
			cl_log(LOG_ERR, "tostring failed");
			return HA_FAIL;			
		}
		
		CHECKROOM_INT(truelen+1);
		bp +=truelen;
		
		strcat(bp,"\n");
		bp++;


	}
	if (needhead){
		CHECKROOM_CONST(MSG_END);
		strcat(bp, MSG_END);
		bp += strlen(MSG_END);
	}

	CHECKROOM_INT(1);
	bp[0] = EOS;

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
	
	len = get_stringlen(m);
	
	if (len >= MAXMSG){
		cl_log(LOG_ERR, "msg2string: msg is too large"
		       "len =%d,MAX msg allowed=%d", len, MAXMSG);
		return NULL;
	}
	
	buf = ha_malloc(len);


	if (buf == NULL) {
		cl_log(LOG_ERR, "msg2string: no memory for string");
		return(NULL);
	}

	if (msg2string_buf(m, buf, len ,0, NEEDHEAD) != HA_OK){
		cl_log(LOG_ERR, "msg2string: msg2string_buf failed");
		ha_free(buf);
		return(NULL);
	}
	
	return(buf);
}

gboolean
must_use_netstring(const struct ha_msg* msg)
{
	int	i; 
	
	for ( i = 0; i < msg->nfields; i++){
		if (msg->types[i] == FT_COMPRESS
		    || msg->types[i] == FT_UNCOMPRESS
		    || msg->types[i] ==  FT_STRUCT){
			return TRUE;
		}
	}
	
	return FALSE;

}


static char*
msg2wirefmt_ll(struct ha_msg*m, size_t* len, int flag)
{
	
	int	wirefmtlen;
	int	i;
	char*	ret;
	

	if (msgfmt == MSGFMT_NETSTRING){
		wirefmtlen = get_netstringlen(m);		
	}else{
		wirefmtlen =  get_stringlen(m);	
	}
	
	if (use_traditional_compression
	    &&(flag & MSG_NEEDCOMPRESS) 
 	    && (wirefmtlen> compression_threshold) 
 	    && cl_get_compress_fns() != NULL){ 
 		return cl_compressmsg(m, len);		 
 	} 
	
	
	for (i=0 ;i < m->nfields; i++){
		int type = m->types[i];
		if (fieldtypefuncs[type].prepackaction){
			fieldtypefuncs[type].prepackaction(m,i);
		}
	}
	
	
	if (msgfmt == MSGFMT_NETSTRING || must_use_netstring(m)){
		wirefmtlen = get_netstringlen(m);		
		if (wirefmtlen >= MAXMSG){
			cl_log(LOG_ERR, "%s: msg too big(%d)"
			       "for netstring fmt",
			       __FUNCTION__, wirefmtlen);
			return NULL;
		}
		if (flag& MSG_NEEDAUTH){
			return msg2netstring(m, len);
		}else{
			ret =  msg2netstring_noauth(m, len);
			return ret;

		}
		
		
	}else{
		char	*tmp;
		
		wirefmtlen =  get_stringlen(m);
		if (wirefmtlen >= MAXMSG){
			cl_log(LOG_ERR, "%s: msg too big(%d)"
			       " for string fmt",
			       __FUNCTION__, wirefmtlen);
			return NULL;
		}
		
		tmp = msg2string(m);
		
		if(tmp == NULL){
			*len = 0;
			return NULL;
		}
		
		*len = strlen(tmp) + 1;
		return(tmp);
	}
	

}


char*
msg2wirefmt(struct ha_msg*m, size_t* len){
	return msg2wirefmt_ll(m, len, MSG_NEEDAUTH|MSG_NEEDCOMPRESS);
}


char*
msg2wirefmt_noac(struct ha_msg*m, size_t* len){
	
	return msg2wirefmt_ll(m, len, 0);
}


static struct ha_msg*
wirefmt2msg_ll(const char* s, size_t length, int need_auth)
{

	size_t startlen;
	struct ha_msg* msg = NULL;	


	startlen = sizeof(MSG_START)-1;
	
	if (startlen > length){
		return NULL;
	}

	if (strncmp( s, MSG_START, startlen) == 0) {
		msg = string2msg_ll(s, length, 0, need_auth);
		goto out;
	}

	startlen = sizeof(MSG_START_NETSTRING) - 1;
	
	if (startlen > length){
		return NULL;
	}
	
	if (strncmp(s, MSG_START_NETSTRING, startlen) == 0) {
		msg =  netstring2msg(s, length, need_auth);
		goto out;
	}

out:
        if (msg && is_compressed_msg(msg)){
                struct ha_msg* ret;
                if ((ret = cl_decompressmsg(msg))==NULL){
                        cl_log(LOG_ERR, "decompress msg failed");
                        ha_msg_del(msg);
                        return NULL;
                }
                ha_msg_del(msg);
                return ret;
	}
	return msg;

}




struct ha_msg*
wirefmt2msg(const char* s, size_t length, int flag)
{
 	return wirefmt2msg_ll(s, length, flag& MSG_NEEDAUTH);

}


void
cl_log_message (int log_level, const struct ha_msg *m)
{
	int	j;
	
	if(m == NULL) {
		cl_log(log_level, "MSG: No message to dump");
		return;
	}
	
	cl_log(log_level, "MSG: Dumping message with %d fields", m->nfields);
	
	for (j=0; j < m->nfields; ++j) {
		
		if(m->types[j] < DIMOF(fieldtypefuncs)){					
			fieldtypefuncs[m->types[j]].display(log_level, j, 
							    m->names[j],
							    m->values[j]);
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
 * Revision 1.94  2005/11/01 15:07:14  andrew
 * small log message tweak
 *
 * Revision 1.93  2005/11/01 06:18:23  gshi
 * bp == maxp is fine :)
 *
 * Revision 1.92  2005/11/01 03:50:58  alan
 * Changed some of gshi's string code to be a little more cautious about buffer
 * overruns.
 *
 * Revision 1.91  2005/11/01 03:05:20  alan
 * Fixed what looks like a bug in cl_msg.c
 * The code sets an end of string marker, and then after it does it looks
 * to see if it was out of bounds.
 * I reversed the order.
 *
 * Revision 1.90  2005/10/31 22:12:29  gshi
 * include name in the warning
 *
 * Revision 1.89  2005/10/31 17:36:30  gshi
 * print out a warning if a big child msg is added
 * without using the compression method
 *
 * Revision 1.88  2005/10/20 17:40:24  gshi
 * fix a 64bit compiling problem
 *
 * Revision 1.87  2005/10/20 00:47:52  gshi
 * add the function to dump msg stats into a file
 *
 * Revision 1.86  2005/10/18 17:35:11  gshi
 * make the default compression traditional
 *
 * Revision 1.85  2005/10/17 19:47:44  gshi
 * add an option to use "traditional" compression method
 * traditional_compression yes/no
 * in ha.cf
 *
 * Revision 1.84  2005/10/17 19:13:48  gshi
 *  change cl_get_struct(const char* msg, ...) to cl_get_struct(char* msg, ...)
 *
 *  make cl_get_struct() handles three types(FT_STRUCT, FT_COMPRESS, FT_UMCOMPRESS)
 *
 * Revision 1.83  2005/10/15 02:52:34  gshi
 * added two APIs
 *
 * ha_msg_addstruct_compress()
 * cl_get_struct_compress()
 *
 * these two APIs must be used in pair to put/get fields in a message
 *
 * Internally two message types are added in order to make the compression
 * only happens in child process instead of the master control process.
 *
 * If transparently comperssing messages is desired, it can be done in interface without
 * internal structure change.
 *
 * Revision 1.82  2005/10/14 18:51:06  gshi
 * remove stringlen in struct ha_msg
 * every time string length for an ha_msg is computed on the fly
 *
 * Revision 1.81  2005/10/13 22:57:13  gshi
 * fix a compiling error in ia64
 *
 * Revision 1.80  2005/10/05 17:12:34  gshi
 * We need to dup the string and free it later
 *
 * Revision 1.79  2005/10/04 22:06:58  gshi
 * *** empty log message ***
 *
 * Revision 1.78  2005/09/20 23:45:03  gshi
 * bug 267: remove ont set of uuid add/remove functions
 *
 * Revision 1.77  2005/09/09 17:15:44  gshi
 * rename CRNL to NEWLINE since it only contains newline now
 *
 * Revision 1.76  2005/09/08 20:05:56  gshi
 * we should only use '\n' as delimiter for an ha_msg field
 *
 * Revision 1.75  2005/08/05 19:40:14  gshi
 * add compression capability
 *
 * Revision 1.74  2005/08/01 19:16:43  gshi
 * fix bug 257
 *
 * make netstring encoding more efficient
 *
 * Revision 1.73  2005/07/06 09:41:09  andrew
 * Some more places where printing size_t as an int was a problem.
 *
 * Revision 1.72  2005/07/03 22:15:50  alan
 * Huge number of signed/unsigned comparisons.
 *
 * Revision 1.71  2005/07/01 19:08:42  gshi
 * keep track of ipcmsg in cl_msg.c
 *
 * Revision 1.70  2005/06/08 20:47:25  gshi
 * add a function to dump message stats
 *
 * Revision 1.69  2005/05/13 17:41:56  gshi
 * if the startlen is greater than the length of a given string
 * obviously it is not a valid message string
 *
 * Revision 1.68  2005/05/05 17:37:33  gshi
 * Store the channel fail reason into a string stored in  channel
 * instead of print out using cl_log. The reason is someone may try to send
 * a message again ang again and we do not want to overflow cl_log
 *
 * Revision 1.67  2005/05/02 20:00:04  gshi
 * change wirefmt2msg() from
 * struct ha_msg* wirefmt2msg(char* string, int len)
 * to
 * struct ha_msg* wirefmt2msg(char* string, int len, int flag)
 * (flag can be 0 or MSG_NEEDAUTH right now)
 *
 * so that we allow a user to convert a string to an ha_msg without
 * authentication.
 *
 * Revision 1.66  2005/04/27 05:31:42  gshi
 *  use struct cl_uuid_t to replace uuid_t
 * use cl_uuid_xxx to replace uuid_xxx funcitons
 *
 * Revision 1.65  2005/03/24 16:36:18  gshi
 * add more log messages in case of send failure
 *
 * Revision 1.64  2005/03/18 23:22:16  gshi
 * add a parameter (int flag) to msgfromIPC()
 * flag can have the following bit set
 * if (flag & MSG_NEEDAUTH): authentication is required for the message
 * if (flag & MSG_ALLOWINTR): if there is interruption which causes recv() to return
 * 			   return NULL.
 *
 * most of time, it is called with flag = 0
 *
 * Revision 1.63  2005/03/15 01:37:38  gshi
 * fix IA64 compiling warnings
 *
 * Revision 1.62  2005/03/15 01:01:09  gshi
 * enable message auditing
 *
 * Revision 1.61  2005/03/15 00:01:23  gshi
 * size of msg->vlens[0] and msg->nlens[0] are diffent in ia64, don't mix them
 *
 * Revision 1.60  2005/03/07 20:01:28  gshi
 * remove function ha_msg_add_str_list() (it is replaced by cl_msg_add_list() )
 *
 * Revision 1.59  2005/03/02 22:54:29  alan
 * Fixed a number of signed/unsigned comparisions
 *
 * Revision 1.58  2005/02/25 11:16:55  lars
 * size_t != int
 *
 * Revision 1.57  2005/02/24 21:17:58  gshi
 * add two APIs for list support
 *
 * Revision 1.56  2005/02/24 20:46:29  gshi
 * BEAM FIX:
 *
 * add list of int support in ha_msg
 * beam fix in ccm
 *
 * Revision 1.55  2005/02/17 21:45:35  gshi
 *  use DIMOF to calculate dimention of an array
 *
 * Revision 1.54  2005/02/17 18:14:22  gshi
 * BEAM fix:
 * add surrounding {} for some if statements
 *
 * Revision 1.53  2005/02/17 15:49:50  alan
 * Fixed a few BEAM complaints (but not all of them yet)
 *
 * Revision 1.52  2005/02/16 20:38:29  alan
 * tried to move around a BEAM comment so it makes it shut up at the right time.
 *
 * Revision 1.51  2005/02/16 19:14:35  gshi
 * Don't check a message's stringlen/netstringlen until it is time to encode the message to string or netstring
 *
 * Revision 1.50  2005/02/16 06:54:51  zhenh
 * add cl_malloc_forced_for_glib() to lrmd.
 *
 * Revision 1.49  2005/02/14 21:16:20  gshi
 * fix a warning in IA64 machine
 *
 * Revision 1.48  2005/02/14 21:06:11  gshi
 * BEAM fix:
 *
 * replacing the binary usage in core code with uuid function
 *
 * Revision 1.47  2005/02/09 18:57:12  gshi
 * In case of one field printing to string failure, we should discard the entire message
 *
 * Revision 1.46  2005/02/09 01:45:05  gshi
 * 1.add a magic number in strut SOCKET_MSG_HEAD. On IPC receive side, it checks that magic
 * number and abort if not correct
 *
 * 2. fixed a bug in IPC: there must be one pool per channel, not one pool per program
 *
 * Revision 1.45  2005/02/08 08:10:27  gshi
 * change the way stringlen and netstringlen is computed.
 *
 * Now it is computed resursively in child messages in get_stringlen() and get_netstringlen()
 * so it allows changing child messages dynamically.
 *
 * Revision 1.44  2005/02/07 21:32:38  gshi
 * move the free from the calling function in wirefmt2ipcmsg() to the caller
 *
 * Revision 1.43  2005/02/07 18:04:37  gshi
 * Serious bug fix.
 *
 * p should not be assigned to msg_body since msg_body is already assigned
 * and p is freed.
 *
 * Revision 1.42  2005/02/07 13:56:15  andrew
 * Back out some test code
 *
 * Revision 1.41  2005/02/07 11:46:42  andrew
 * Implement some needed variations of cl_msg_remove()
 *
 * Revision 1.40  2005/02/06 05:54:42  alan
 * Miscellaneous BEAM fixes.
 * Memory leaks, use of NULL pointers, etc.
 * Two errors are just pointed out and not fixed.  One is serious.
 *
 * Revision 1.39  2005/01/28 09:09:51  gshi
 * add function to remove a field
 *
 * Revision 1.38  2005/01/26 13:57:07  andrew
 * Make value a const argument for consistency
 *
 * Revision 1.37  2005/01/18 20:33:04  andrew
 * Appologies for the top-level commit, one change necessitated another which
 *   exposed some bugs... etc etc
 *
 * Remove redundant usage of XML in the CRM
 * - switch to "struct ha_msg" aka. HA_Message for everything except data
 * Make sure the expected type of all FSA input data is verified before processing
 * Fix a number of bugs including
 * - looking in the wrong place for the API result data in the CIB API
 *   (hideous that this actually worked).
 * - not overwriting error codes when sending the result to the client in the CIB API
 *   (this lead to some error cases being treated as successes later in the code)
 * Add PID to log messages sent to files (not to syslog)
 * Add a log level to calls for cl_log_message()
 * - convert existing calls, sorry if I got the level wrong
 * Add some checks in cl_msg.c code to prevent NULL pointer exceptions
 * - usually when NULL is passed to strlen() or similar
 *
 * Revision 1.36  2004/12/05 19:20:56  andrew
 * ha_msg_value_int() calls cl_get_value() which takes a const msg and ha_msg_value_int()
 *   doesnt modify anything so I think this is correct.  Its also helpful since
 *   llc_msg_callback_t must take a const msg.
 *
 * Revision 1.35  2004/12/05 04:32:50  gshi
 * Moved some message-related functions from lrm_msg.c to cl_msg.c
 * These functions are general and shall be available to other subsystems
 *
 * Revision 1.34  2004/11/22 20:06:42  gshi
 * new IPC message should be memset-ed to 0
 * to avoid errors caused by adding a new field (void*) msg_buf
 *
 * Revision 1.33  2004/11/18 00:34:37  gshi
 * 1. use one system call send() instead of two for each message in IPC.
 * 2. fixed a bug: heartbeat could crash if IPC pipe beween heartbeat and a client
 * is full.
 *
 * Revision 1.32  2004/11/17 22:03:43  lars
 * Fix another type error.
 *
 * Revision 1.31  2004/11/04 23:53:30  gshi
 * when adding a binary field, even it's length is zero,
 * I still allocate 1-byte length memory for it and store '\0' in it
 * there no field will have a NULL value
 *
 * Revision 1.30  2004/11/04 22:56:11  gshi
 * fixed a bug in 0-length binary field
 *
 * Revision 1.29  2004/11/04 21:19:29  gshi
 * added zero length binary field support
 *
 * Revision 1.28  2004/10/18 21:13:25  alan
 * Added functions to get/put/modify uuid fileds in our msgs...
 *
 * Revision 1.27  2004/10/03 07:25:44  gshi
 * BEAM fix:
 * fixed some memory leak problems
 *
 * Revision 1.26  2004/09/30 06:02:23  gshi
 * modulize the message for types
 * all type-related functions are moved the new file cl_msg_types.c
 *
 * This make code cleaner to read
 * and make adding a new type to ha_msg field easier: simly implement the given struct
 *
 * Revision 1.25  2004/09/27 08:47:13  zhenh
 * getting a non-existing field should not get a warning
 *
 * Revision 1.24  2004/09/23 03:46:43  gshi
 * fixed a sprintf format warning
 * fixed some comments
 *
 * Revision 1.23  2004/09/22 22:41:10  gshi
 * add list support for ha_msg
 * it supports list of strings only
 *
 * Revision 1.22  2004/09/22 17:03:23  gshi
 * brought STABLE change back to HEAD branch
 *
 * Revision 1.21  2004/09/09 20:34:49  gshi
 * fixed a bug
 * the third argument of strncmp should not be netstring_startlen
 * instread of (netstring_startlen == 0)
 *
 * Revision 1.20  2004/08/31 18:42:51  alan
 * Put in the code to suppress warnings about bad packets...
 *
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
