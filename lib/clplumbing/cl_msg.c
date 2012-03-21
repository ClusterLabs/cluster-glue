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

#include <lha_internal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/utsname.h>
#include <ha_msg.h>
#include <unistd.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/ipc.h>
#include <clplumbing/base64.h>
#include <clplumbing/netstring.h>
#include <glib.h>
#include <clplumbing/cl_uuid.h>
#include <compress.h>
#include <clplumbing/timers.h>
#include <clplumbing/cl_signal.h>

#define		MAXMSGLINE	512
#define		MINFIELDS	30
#define		NEWLINE		"\n"


#define		NEEDAUTH	1
#define		NOAUTH		0
#define		MAX_INT_LEN 	64
#define		MAX_NAME_LEN 	255
#define		UUID_SLEN	64
#define		MAXCHILDMSGLEN  512

static int	compression_threshold = (128*1024);

static enum cl_msgfmt msgfmt = MSGFMT_NVPAIR;
static	gboolean use_traditional_compression = FALSE;

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

#undef DOPARANOIDAUDITS
/* #define DOPARANOIDAUDITS */

#ifdef DOAUDITS
void ha_msg_audit(const struct ha_msg* msg);
#	define	AUDITMSG(msg)		ha_msg_audit(msg)
#  ifdef DOPARANOIDAUDITS
#	define	PARANOIDAUDITMSG(msg)	ha_msg_audit(msg)
#  else
#	define	PARANOIDAUDITMSG(msg)	/*nothing*/
#  endif
#else
#	define	AUDITMSG(msg)		/*nothing*/
#	define	PARANOIDAUDITMSG(msg)	/*nothing*/
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
extern GHashTable*		CompressFuncs;


void
cl_set_traditional_compression(gboolean value)
{
	use_traditional_compression = value;
	if (use_traditional_compression && CompressFuncs) {
		cl_log(LOG_WARNING
		,	"Traditional compression selected"
		". Realtime behavior will likely be impacted(!)");
		cl_log(LOG_INFO
		,	"See %s for more information."
		,	HAURL("Ha.cf#traditional_compression_-_controls_compression_mode"));
	}
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
	
	return open(filename, O_WRONLY|O_CREAT|O_APPEND, 0644);

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
		free(element);
	}
	g_list_free(list);
}



/* Create a new (empty) message */
struct ha_msg *
ha_msg_new(int nfields)
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
		ret->names     = (char **)calloc(sizeof(char *), nalloc);
		ret->nlens     = (size_t *)calloc(sizeof(size_t), nalloc);
		ret->values    = (void **)calloc(sizeof(void *), nalloc);
		ret->vlens     = (size_t *)calloc(sizeof(size_t), nalloc);
		ret->types	= (int*)calloc(sizeof(int), nalloc);

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
		PARANOIDAUDITMSG(msg);
		if (msgstats) {
			msgstats->allocmsgs--;
		}
		if (msg->names) {
			for (j=0; j < msg->nfields; ++j) {
				if (msg->names[j]) {
					free(msg->names[j]);
					msg->names[j] = NULL;
				}
			}
			free(msg->names);
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
			free(msg->values);
			msg->values = NULL;
		}
		if (msg->nlens) {
			free(msg->nlens);
			msg->nlens = NULL;
		}
		if (msg->vlens) {
			free(msg->vlens);
			msg->vlens = NULL;
		}
		if (msg->types){
			free(msg->types);
			msg->types = NULL;
		}
		msg->nfields = -1;
		msg->nalloc = -1;
		free(msg);
	}
}
struct ha_msg*
ha_msg_copy(const struct ha_msg *msg)
{
	struct ha_msg*		ret;
	int			j;

	
	PARANOIDAUDITMSG(msg);
	if (msg == NULL || (ret = ha_msg_new(msg->nalloc)) == NULL) {   
		return NULL;   
	} 

	ret->nfields	= msg->nfields;

	memcpy(ret->nlens, msg->nlens, sizeof(msg->nlens[0])*msg->nfields);
	memcpy(ret->vlens, msg->vlens, sizeof(msg->vlens[0])*msg->nfields);
	memcpy(ret->types, msg->types, sizeof(msg->types[0])*msg->nfields);

	for (j=0; j < msg->nfields; ++j) {
		
		if ((ret->names[j] = malloc(msg->nlens[j]+1)) == NULL) {
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
	if (!msg) {
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

	if (!msg->names) {
		cl_log(LOG_CRIT
		,	"Message names @ %p is not allocated"
		,	 msg->names);
		doabort = TRUE;
	}
	if (!msg->values) {
		cl_log(LOG_CRIT
		,	"Message values @ %p is not allocated"
		,	msg->values);
		doabort = TRUE;
	}
	if (!msg->nlens) {
		cl_log(LOG_CRIT
		,	"Message nlens @ %p is not allocated"
		,	msg->nlens);
		doabort = TRUE;
	}
	if (!msg->vlens) {
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
		
		if (msg->nlens[j] == 0){
			cl_log(LOG_ERR, "zero namelen found in msg");
			abort();
		}
		
		if (msg->types[j] == FT_STRING){
			if (msg->vlens[j] != strlen(msg->values[j])){
				cl_log(LOG_ERR, "stringlen does not match");
				cl_log_message(LOG_INFO,msg);
				abort();
			}
		}
		
		if (!msg->names[j]) {
			cl_log(LOG_CRIT, "Message name[%d] @ 0x%p"
			       " is not allocated." ,	
			       j, msg->names[j]);
			abort();
		}
		if (msg->types[j] != FT_LIST && !msg->values[j]) {
			cl_log(LOG_CRIT, "Message value [%d] @ 0x%p"
			       " is not allocated.",  j, msg->values[j]);
			cl_log_message(LOG_INFO, msg);
			abort();
		}
	}
}
#endif



int
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
	msg->names = 	(char **)calloc(sizeof(char *), nalloc);
	msg->nlens = 	(size_t *)calloc(sizeof(size_t), nalloc);
	msg->values = 	(void **)calloc(sizeof(void *), nalloc);
	msg->vlens = 	(size_t *)calloc(sizeof(size_t), nalloc);
	msg->types= 	(int*)calloc(sizeof(int), nalloc);
	
	if (msg->names == NULL || msg->values == NULL
	    ||	msg->nlens == NULL || msg->vlens == NULL
	    ||	msg->types == NULL) {
		
		cl_log(LOG_ERR, "%s"
		       ,	" out of memory for ha_msg");		
		return(HA_FAIL);
	}
	
	memcpy(msg->names, names, msg->nalloc*sizeof(char *));
	memcpy(msg->nlens, nlens, msg->nalloc*sizeof(size_t));
	memcpy(msg->values, values, msg->nalloc*sizeof(void *));
	memcpy(msg->vlens, vlens, msg->nalloc*sizeof(size_t));
	memcpy(msg->types, types, msg->nalloc*sizeof(int));
	
	free(names);
	free(nlens);
	free(values);
	free(vlens);
	free(types);
	
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
		
	free(msg->names[j]);
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
	
	if (namelen >= startlen
	    && name[0] == '>'
	    && strncmp(name, MSG_START, startlen) == 0) {
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
	
	HA_MSG_ASSERT(type < DIMOF(fieldtypefuncs));
	
	addfield =  fieldtypefuncs[type].addfield;
	if (!addfield || 
	    addfield(msg, name, namelen, value, vallen,depth) != HA_OK){
		cl_log(LOG_ERR, "ha_msg_addraw_ll: addfield failed");
		return(HA_FAIL);
	}
	
	PARANOIDAUDITMSG(msg);

	return(HA_OK);


}

static int
ha_msg_addraw(struct ha_msg * msg, const char * name, size_t namelen,
	      const void * value, size_t vallen, int type, int depth)
{

	char	*cpvalue = NULL;
	char	*cpname = NULL;
	int	ret;


	if (namelen == 0){
		cl_log(LOG_ERR, "%s: Adding a field with 0 name length", __FUNCTION__);
		return HA_FAIL;
	}
	
	if ((cpname = malloc(namelen+1)) == NULL) {
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
		free(cpname);
		return(HA_FAIL);
	}
	
	ret = ha_msg_addraw_ll(msg, cpname, namelen, cpvalue, vallen
	,	type, depth);

	if (ret != HA_OK){
		cl_log(LOG_ERR, "ha_msg_addraw(): ha_msg_addraw_ll failed");
		free(cpname);
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
		/*cl_log(LOG_WARNING,
		       "%s: childmsg too big (name=%s, nslen=%d, len=%d)."
		       "   Use ha_msg_addstruct_compress() instead.",
		       __FUNCTION__, name, get_netstringlen(childmsg), 
		       get_stringlen(childmsg));
		*/
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

int
ha_msg_add_ul(struct ha_msg * msg, const char * name, unsigned long value)
{
	char buf[MAX_INT_LEN];
	snprintf(buf, MAX_INT_LEN, "%lu", value);
	return (ha_msg_add(msg, name, buf));	
}

int
ha_msg_mod_ul(struct ha_msg * msg, const char * name, unsigned long value)
{
	char buf[MAX_INT_LEN];
	snprintf(buf, MAX_INT_LEN, "%lu", value);
	return (cl_msg_modstring(msg, name, buf));	
}

int
ha_msg_value_ul(const struct ha_msg * msg, const char * name, unsigned long* value)
{
	const char* svalue = ha_msg_value(msg, name);
	if(NULL == svalue) {
		return HA_FAIL;
	}
	*value = strtoul(svalue, NULL, 10);
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
		cl_log(LOG_ERR
		       , "ha_msg_addstruct in ha_msg_add_str_table failed");
		return HA_FAIL;
	}
	ha_msg_del(hash_msg);
	return HA_OK;
}

int
ha_msg_mod_str_table(struct ha_msg * msg, const char * name,
			GHashTable* hash_table)
{
	struct ha_msg* hash_msg;
	if (NULL == msg || NULL == name || NULL == hash_table) {
		return HA_FAIL;
	}

	hash_msg = str_table_to_msg(hash_table);
	if( HA_OK != cl_msg_modstruct(msg, name, hash_msg)) {
		ha_msg_del(hash_msg);
		cl_log(LOG_ERR
		       , "ha_msg_modstruct in ha_msg_mod_str_table failed");
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
	
	if(!msg || !name || !value){
		cl_log(LOG_ERR, "cl_msg_list_add_string: input invalid");
		return HA_FAIL;
	}
	
	
	list = g_list_append(list, UNCONST_CAST_POINTER(gpointer, value));
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
		cl_log(LOG_ERR, "%s: wrong argument (%s)",
		       __FUNCTION__, name);
		return(NULL);
	}

	PARANOIDAUDITMSG(msg);
	for (j=0; j < msg->nfields; ++j) {
		const char *local_name = msg->names[j];
		if (name[0] == local_name[0]
		    && strcmp(name, local_name) == 0) {
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
		cl_log(LOG_ERR, "%s: wrong argument",
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

int 
cl_msg_replace_value(struct ha_msg* msg, const void *old_value,
		     const void* value, size_t vlen, int type)
{
	int j;
	
	if (msg == NULL || old_value == NULL) {
		cl_log(LOG_ERR, "cl_msg_replace: invalid argument");
		return HA_FAIL;
	}
	
	for (j = 0; j < msg->nfields; ++j){
		if (old_value == msg->values[j]){
			break;			
		}
	}
	if (j == msg->nfields){		
		cl_log(LOG_ERR, "cl_msg_replace: field %p not found", old_value);
		return HA_FAIL;
	}
	return cl_msg_replace(msg, j, value, vlen, type);
}

/*this function is for internal use only*/
int 
cl_msg_replace(struct ha_msg* msg, int index,
	       const void* value, size_t vlen, int type)
{
	void *	newv ;
	int	newlen = vlen;
	int	oldtype;
	
	PARANOIDAUDITMSG(msg);
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
	PARANOIDAUDITMSG(msg);
	return(HA_OK);
	
}


static int
cl_msg_mod(struct ha_msg * msg, const char * name,
	       const void* value, size_t vlen, int type)
{  
  	int j;
	int rc;	

	PARANOIDAUDITMSG(msg);
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
			PARANOIDAUDITMSG(msg);
			return(HA_OK);
		}
	}
	
	rc = ha_msg_nadd_type(msg, name,strlen(name), value, vlen, type);
  
	PARANOIDAUDITMSG(msg);
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

		nvpair = malloc(nvlen + 2);
		
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

static gboolean ipc_timer_expired = FALSE;

static void cl_sigalarm_handler(int signum)
{
        if (signum == SIGALRM) {
                ipc_timer_expired = TRUE;
        }
}

int
cl_ipc_wait_timeout(
    IPC_Channel *chan, int (*waitfun)(IPC_Channel *chan), unsigned int timeout)
{
        int rc = IPC_FAIL;
        struct sigaction old_action;

	memset(&old_action, 0, sizeof(old_action));
	cl_signal_set_simple_handler(SIGALRM, cl_sigalarm_handler, &old_action);

	ipc_timer_expired = FALSE;

	alarm(timeout);
	rc = waitfun(chan);
	if (rc == IPC_INTR && ipc_timer_expired) {
	    rc = IPC_TIMEOUT;
	}

	alarm(0); /* ensure it expires */
	cl_signal_set_simple_handler(SIGALRM, old_action.sa_handler, &old_action);


        return rc;
}

/* Return the next message found in the IPC channel */
static struct ha_msg*
msgfromIPC_ll(IPC_Channel * ch, int flag, unsigned int timeout, int *rc_out)
{
	int		rc;
	IPC_Message*	ipcmsg;
	struct ha_msg*	hmsg;
	int		need_auth = flag & MSG_NEEDAUTH;
	int		allow_intr = flag & MSG_ALLOWINTR;
	
 startwait:
	if(timeout > 0) {
	    rc = cl_ipc_wait_timeout(ch, ch->ops->waitin, timeout);
	} else {
	    rc = ch->ops->waitin(ch);
	}

	if(rc_out) {
	    *rc_out = rc;
	}
	
	switch(rc) {
	default:
	case IPC_FAIL:
		cl_perror("msgfromIPC: waitin failure");
		return NULL;

	case IPC_TIMEOUT:
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
	if(rc_out) {
	    *rc_out = rc;
	}

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
msgfromIPC_timeout(IPC_Channel *ch, int flag, unsigned int timeout, int *rc_out)
{
    return msgfromIPC_ll(ch, flag, timeout, rc_out);
}

struct ha_msg*
msgfromIPC(IPC_Channel * ch, int flag)
{
	return msgfromIPC_ll(ch, flag, 0, NULL);
}


struct ha_msg*
msgfromIPC_noauth(IPC_Channel * ch)
{
	int flag = 0;
	
	flag |= MSG_ALLOWINTR;
	return msgfromIPC_ll(ch, flag, 0, NULL);
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
		free(s);
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
		free(m->msg_buf);
	}
	free(m);
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
	
	if (NULL == (ret->msg_buf = malloc(len + ch->msgpad))) {
		free(ret);
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
	char *		s  = msg2wirefmt_ll(m, &len, MSG_NEEDCOMPRESS);
	IPC_Message*	ret = NULL;

	if (s == NULL) {
		return ret;
	}
	ret = MALLOCT(IPC_Message);
	if (!ret) {
		free(s);
		return ret;
	}
	
	memset(ret, 0, sizeof(IPC_Message));

	if (NULL == (ret->msg_buf = malloc(len + ch->msgpad))) {
		free(s);
		free(ret);
		return NULL;
	}
	ret->msg_body = (char*)ret->msg_buf + ch->msgpad;
	memcpy(ret->msg_body, s, len);
	free(s);
	
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
		cl_log(LOG_ERR, "%s: creating new msg failed", __FUNCTION__);
		return(NULL);
	}
	
	startlen = sizeof(MSG_START)-1;
	if (strncmp(sp, MSG_START, startlen) != 0) {
		/* This can happen if the sender gets killed */
		/* at just the wrong time... */
		if (!cl_msg_quiet_fmterr) {
			cl_log(LOG_WARNING, "string2msg_ll: no MSG_START");
			cl_log(LOG_WARNING, "%s: s=%s", __FUNCTION__, s);
			cl_log(LOG_WARNING,  "depth=%d", depth);
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
			cl_log(LOG_ERR, "%s: buffer overflow(sp=%p, smax=%p)",
			       __FUNCTION__, sp, smax);
			return(NULL);
		}
		/* Skip over initial CR/NL things */
		sp += strspn(sp, NEWLINE);
		if (sp >= smax)	{
			cl_log(LOG_ERR, "%s: buffer overflow after NEWLINE(sp=%p, smax=%p)",
			       __FUNCTION__, sp, smax);
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
				cl_log(LOG_ERR, "depth=%d", depth);				
				cl_log_message(LOG_ERR,ret);
			}			
			ha_msg_del(ret);
			return(NULL);
		}
		if (sp >= smax) {
			cl_log(LOG_ERR, "%s: buffer overflow after adding field(sp=%p, smax=%p)",
			       __FUNCTION__, sp, smax);
			return(NULL);
		}
		sp += strcspn(sp, NEWLINE);
	}
	
	if (need_auth && msg_authentication_method
	    &&		!msg_authentication_method(ret)) {
		const char* from = ha_msg_value(ret, F_ORIG);
		if (!cl_msg_quiet_fmterr) {
			cl_log(LOG_WARNING,
			       "string2msg_ll: node [%s]"
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
			cl_log(LOG_ERR, "tostring failed for field %d", j);
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
	
	buf = malloc(len);

	if (buf == NULL) {
		cl_log(LOG_ERR, "msg2string: no memory for string");
		return(NULL);
	}

	if (msg2string_buf(m, buf, len ,0, NEEDHEAD) != HA_OK){
		cl_log(LOG_ERR, "msg2string: msg2string_buf failed");
		free(buf);
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

#define use_netstring(m) (msgfmt == MSGFMT_NETSTRING || must_use_netstring(m))

static char*
msg2wirefmt_ll(struct ha_msg*m, size_t* len, int flag)
{
	
	int	wirefmtlen;
	int	i;
	int	netstg = use_netstring(m);

	wirefmtlen = netstg ? get_netstringlen(m) : get_stringlen(m);
	if (use_traditional_compression
	    &&(flag & MSG_NEEDCOMPRESS) 
 	    && (wirefmtlen> compression_threshold) 
 	    && cl_get_compress_fns() != NULL){ 
 		return cl_compressmsg(m, len);		 
 	} 

	if (flag & MSG_NEEDCOMPRESS){
		for (i=0 ;i < m->nfields; i++){
			int type = m->types[i];
			if (fieldtypefuncs[type].prepackaction){
				fieldtypefuncs[type].prepackaction(m,i);
			}
		}
	}

	wirefmtlen = netstg ? get_netstringlen(m) : get_stringlen(m);
	if (wirefmtlen >= MAXMSG){
		if (flag&MSG_NEEDCOMPRESS) {
			if (cl_get_compress_fns() != NULL)
				return cl_compressmsg(m, len);
		}
		cl_log(LOG_ERR, "%s: msg too big(%d)",
			   __FUNCTION__, wirefmtlen);
		return NULL;
	}
	if (flag & MSG_NEEDAUTH) {
		return msg2netstring(m, len);
	}
	return msg2wirefmt_noac(m, len);
}

char*
msg2wirefmt(struct ha_msg*m, size_t* len){
	return msg2wirefmt_ll(m, len, MSG_NEEDAUTH|MSG_NEEDCOMPRESS);
}

char*
msg2wirefmt_noac(struct ha_msg*m, size_t* len)
{
	if (use_netstring(m)) {
		return msg2netstring_noauth(m, len);
	} else {
		char	*tmp;

		tmp = msg2string(m);
		if(tmp == NULL){
			*len = 0;
			return NULL;
		}
		*len = strlen(tmp) + 1;
		return tmp;
	}
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
							    m->values[j],
							    m->vlens[j]);
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
