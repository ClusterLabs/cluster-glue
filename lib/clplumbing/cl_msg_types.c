/*
 * Heartbeat message type functions
 *
 * Copyright (C) 2004 Guochun Shi <gshi@ncsa.uiuc.edu>
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

#ifndef MAX
#	define MAX(a,b)	(((a) > (b)) ? (a) : (b))
#endif


extern const char* FT_strings[];



#define		NL_TO_SYM	0
#define		SYM_TO_NL	1

static const int SPECIAL_SYMS[MAXDEPTH] = {
	20,
	21,
	22,
	23,
	24,
	25,
	26,
	27,
	28,
	29,
	30,
	31,
	15,
	16,
	17,
	18,
};

#define	       SPECIAL_SYM	19

struct ha_msg* string2msg_ll(const char*, size_t, int, int);
int compose_netstring(char*, const char*, const char*, size_t, size_t*);
int msg2netstring_buf(const struct ha_msg*, char*, size_t, size_t*);
int struct_display_print_spaces(char *buffer, int depth);
int struct_display_as_xml(int log_level, int depth, struct ha_msg *data,
			  const char *prefix, gboolean formatted);
int struct_stringlen(size_t namlen, size_t vallen, const void* value);
int struct_netstringlen(size_t namlen, size_t vallen, const void* value);
int	convert_nl_sym(char* s, int len, char sym, int direction);
int	bytes_for_int(int x);

int
bytes_for_int(int x)
{
	int len = 0;
	if(x < 0) {
		x = 0-x;
		len=1;
	}
	while(x > 9) {
		x /= 10;
		len++;
	}
 	return len+1;
}

int
netstring_extra(int x)
{
	return (bytes_for_int(x) + x + 2);
}

int
get_netstringlen(const struct ha_msg *m)
{
	int i;
	int total_len =0 ;
	
	if (m == NULL){
		cl_log(LOG_ERR, "get_netstringlen:"
		       "asking netstringlen of a NULL message");
		return 0;
	}
	
	total_len = sizeof(MSG_START_NETSTRING)
		+ sizeof(MSG_END_NETSTRING) -2 ;
	
	
	for (i = 0; i < m->nfields; i++){		
		int len;
		len = fieldtypefuncs[m->types[i]].netstringlen(m->nlens[i], 
							       m->vlens[i],
							       m->values[i]);
		total_len += netstring_extra(len);
	}
	
	
	return total_len;	
	
	
}



int
get_stringlen(const struct ha_msg *m)
{
	int i;
	int total_len =0 ;

	if (m == NULL){
		cl_log(LOG_ERR, "get_stringlen:"
		       "asking stringlen of a NULL message");
		return 0;
	}
	
	total_len = sizeof(MSG_START)+sizeof(MSG_END)-1;	
	
	for (i = 0; i < m->nfields; i++){				
		total_len += fieldtypefuncs[m->types[i]].stringlen(m->nlens[i], 
								   m->vlens[i],
								   m->values[i]);	
	}
	
	return total_len;
}



/*
  compute the total size of the resulted string
  if the string list is to be converted
  
*/
size_t
string_list_pack_length(const GList* _list)
{
	size_t i;
	GList* list = UNCONST_CAST_POINTER(GList *, _list);
	size_t total_length = 0;
	
	if (list == NULL){
		cl_log(LOG_WARNING, "string_list_pack_length():"
		       "list is NULL");

		return 0;
	}
	for (i = 0; i < g_list_length(list) ; i++){
		
		int len = 0;
		char * element = g_list_nth_data(list, i);
		if (element == NULL){
			cl_log(LOG_ERR, "string_list_pack_length: "
			       "%luth element of the string list is NULL"
				, (unsigned long)i);
			return 0;
		}
		len = strlen(element);
		total_length += bytes_for_int(len) + len + 2;
		/* 2 is for ":" and "," */
		}
	return total_length ;
}



/*
  convert a string list into a single string
  the format to convert is similar to netstring:
	<length> ":" <the actual string> ","

  for example, a list containing two strings "abc" "defg"
  will be converted into
	3:abc,4:defg,
  @list: the list to be converted
  @buf:  the converted string should be put in the @buf
  @maxp: max pointer
*/


int
string_list_pack(GList* list, char* buf, char* maxp)
{
	size_t i;
	char* p =  buf;

	for (i = 0; i < g_list_length(list) ; i++){
		char * element = g_list_nth_data(list, i);
		int element_len;

		if (element == NULL){
			cl_log(LOG_ERR, "string_list_pack: "
			       "%luth element of the string list is NULL"
				, (unsigned long)i);
			return 0;
		}
		element_len = strlen(element);
		if (p + 2 + element_len + bytes_for_int(element_len)> maxp){
			cl_log(LOG_ERR, "%s: memory out of boundary",
			       __FUNCTION__);
			return 0;
		}
		p += sprintf(p, "%d:%s,", element_len,element);
		
		if (p > maxp){
			cl_log(LOG_ERR, "string_list_pack: "
			       "buffer overflowed ");
			return 0;
		}		
	}
	
	
	return (p - buf);
}



/* 
   this is reverse process of pack_string_list
*/
GList* 
string_list_unpack(const char* packed_str_list, size_t length)
{
	GList*		list = NULL;
	const char*	psl = packed_str_list;
	const char *	maxp= packed_str_list + length;
	int		len = 0;
	
	
	while(TRUE){
		char* buf;

		if (*psl == '\0' || psl >=  maxp){
			break;
		}
		
		if (sscanf( psl, "%d:", &len) <= 0 ){
			break;
		}
		
		if (len <=0){
			cl_log(LOG_ERR, "unpack_string_list:"
			       "reading len of string error");
			if (list){
				list_cleanup(list);
			}
			return NULL;
		}
		
		while (*psl != ':' && *psl != '\0' ){
			psl++;
		}
		
		if (*psl == '\0'){
			break;
		}
		
		psl++;
		
		buf = malloc(len + 1);
		if (buf == NULL){
			cl_log(LOG_ERR, "unpack_string_list:"
			       "unable to allocate buf");
			if(list){
				list_cleanup(list);
			}
			return NULL;			
			
		}
		memcpy(buf, psl, len);
		buf[len] = '\0';
		list = g_list_append(list, buf);
		psl +=len;
		
		if (*psl != ','){
			cl_log(LOG_ERR, "unpack_string_list:"
			       "wrong format, s=%s",packed_str_list);	
		}
		psl++;
	}
	
	return list;

}


static void
string_memfree(void* value)
{
	if (value){
		free(value);
	}else {
		cl_log(LOG_ERR, "string_memfree: "
		       "value is NULL");
        }


	return;
}

static void
binary_memfree(void* value)
{
	string_memfree(value);
}


static void
struct_memfree( void* value)
{
	struct ha_msg* msg;

	if (!value){
		cl_log(LOG_ERR,
		       "value is NULL");
		return ;
	}
	
	msg = (struct ha_msg*) value;
	ha_msg_del(msg);
	return ;
}

static void
list_memfree(void* value)
{

	if (!value){
		cl_log(LOG_ERR,
		       "value is NULL");
		return ;
	}
	
	list_cleanup(value);	
	
}


static void* 
binary_dup(const void* value, size_t len)
{
	
	char* dupvalue;
	
	/* 0 byte binary field is allowed*/

	if (value == NULL && len > 0){
		cl_log(LOG_ERR, "binary_dup:"
		       "NULL value with non-zero len=%d", 
		       (int)len);
		return NULL;
	}
	
	dupvalue = malloc(len + 1);
	if (dupvalue == NULL){
		cl_log(LOG_ERR, "binary_dup:"
		       "malloc failed");
		return NULL;
	}
	
	if (value != NULL) {
		memcpy(dupvalue, value, len);
	}

	dupvalue[len] =0;
	
	return dupvalue;
}

static void*
string_dup(const void* value, size_t len)
{
	return binary_dup(value, len);
}


static void*
struct_dup(const void* value, size_t len)
{	
	char* dupvalue;
	
	(void)len;

	if (!value){
		cl_log(LOG_ERR,"struct_dup:"
		       "value is NULL");
		return NULL ;
	}
	
	
	dupvalue = (void*)ha_msg_copy((const struct ha_msg*)value);
	if (dupvalue == NULL){
		cl_log(LOG_ERR, "struct_dup: "
		       "ha_msg_copy failed");
		return NULL;
	}
	
	return dupvalue;
}

static GList* 
list_copy(const GList* _list)
{
	size_t i;
	GList* newlist = NULL;
	GList* list = UNCONST_CAST_POINTER(GList *, _list);

	for (i = 0; i < g_list_length(list); i++){
		char* dup_element = NULL;
		char* element = g_list_nth_data(list, i);
		int len;
		if (element == NULL){
			cl_log(LOG_WARNING, "list_copy:"
			       "element is NULL");
			continue;
		}

		len = strlen(element);
		dup_element= malloc(len + 1);
		if ( dup_element == NULL){
			cl_log(LOG_ERR, "duplicate element failed");
			continue;
		}
		memcpy(dup_element, element,len);
		dup_element[len] = 0;
		
		newlist = g_list_append(newlist, dup_element);		
	}
	
	return newlist;
}

static void*
list_dup( const void* value, size_t len)
{
	char* dupvalue;

	(void)len;
	if (!value){
		cl_log(LOG_ERR,"struct_dup:"
		       "value is NULL");
		return NULL ;
	}	
	
	dupvalue = (void*)list_copy((const GList*)value);
	
	if (!dupvalue){
		cl_log(LOG_ERR, "list_dup: "
		       "list_copy failed");
		return NULL;
	}
	
	return dupvalue;
}


static void 
general_display(int log_level, int seq, char* name, void* value, int vlen, int type)
{
	int netslen;
	int slen;
	HA_MSG_ASSERT(value);	
	HA_MSG_ASSERT(name);
	
	slen = fieldtypefuncs[type].stringlen(strlen(name), vlen, value);
	netslen = fieldtypefuncs[type].netstringlen(strlen(name), vlen, value);
	cl_log(log_level, "MSG[%d] : [(%s)%s=%p(%d %d)]",
	       seq,	FT_strings[type],
	       name,	value, slen, netslen);	
	
}
static void
string_display(int log_level, int seq, char* name, void* value, int vlen)
{
	HA_MSG_ASSERT(name);
	HA_MSG_ASSERT(value);
	cl_log(log_level, "MSG[%d] : [%s=%s]",
	       seq, name, (const char*)value);
	return;
}

static void
binary_display(int log_level, int seq, char* name, void* value, int vlen)
{
	general_display(log_level, seq, name, value, vlen, FT_BINARY);
}

static void
compress_display(int log_level, int seq, char* name, void* value, int vlen){
	general_display(log_level, seq, name, value, vlen, FT_COMPRESS);
}


static void
general_struct_display(int log_level, int seq, char* name, void* value, int vlen, int type)
{
	int slen;
	int netslen;

	HA_MSG_ASSERT(name);
	HA_MSG_ASSERT(value);	
	
	slen = fieldtypefuncs[type].stringlen(strlen(name), vlen, value);
	netslen = fieldtypefuncs[type].netstringlen(strlen(name), vlen, value);
	
	cl_log(log_level, "MSG[%d] : [(%s)%s=%p(%d %d)]",
	       seq,	FT_strings[type],
	       name,	value, slen, netslen);
	if(cl_get_string((struct ha_msg*) value, F_XML_TAGNAME) == NULL) {
		cl_log_message(log_level, (struct ha_msg*) value);
	} else {
		/* use a more friendly output format for nested messages */
		struct_display_as_xml(log_level, 0, value, NULL, TRUE);
	}
}
static void
struct_display(int log_level, int seq, char* name, void* value, int vlen)
{
	general_struct_display(log_level, seq, name, value, vlen,  FT_STRUCT);

}
static void
uncompress_display(int log_level, int seq, char* name, void* value, int vlen)
{
	general_struct_display(log_level, seq, name, value, vlen, FT_UNCOMPRESS);
}

#define update_buffer_head(buffer, len) if(len < 0) {	\
		(*buffer) = EOS; return -1;		\
	} else {					\
		buffer += len;				\
	}

int
struct_display_print_spaces(char *buffer, int depth) 
{
	int lpc = 0;
	int spaces = 2*depth;
	/* <= so that we always print 1 space - prevents problems with syslog */
	for(lpc = 0; lpc <= spaces; lpc++) {
		if(sprintf(buffer, "%c", ' ') < 1) {
			return -1;
		}
		buffer += 1;
	}
	return lpc;
}

int
struct_display_as_xml(
	int log_level, int depth, struct ha_msg *data,
	const char *prefix, gboolean formatted) 
{
	int lpc = 0;
	int printed = 0;
	gboolean has_children = FALSE;
	char print_buffer[1000];
	char *buffer = print_buffer;
	const char *name = cl_get_string(data, F_XML_TAGNAME);

	if(data == NULL) {
		return 0;

	} else if(name == NULL) {
		cl_log(LOG_WARNING, "Struct at depth %d had no name", depth);
		cl_log_message(log_level, data);
		return 0;
	}
	
	if(formatted) {
		printed = struct_display_print_spaces(buffer, depth);
		update_buffer_head(buffer, printed);
	}
	
	printed = sprintf(buffer, "<%s", name);
	update_buffer_head(buffer, printed);
	
	for (lpc = 0; lpc < data->nfields; lpc++) {
		const char *prop_name = data->names[lpc];
		const char *prop_value = data->values[lpc];
		if(data->types[lpc] != FT_STRING) {
			continue;
		} else if(prop_name == NULL) {
			continue;
		} else if(prop_name[0] == '_' && prop_name[1] == '_') {
			continue;
		}
		printed = sprintf(buffer, " %s=\"%s\"", prop_name, prop_value);
		update_buffer_head(buffer, printed);
	}

	for (lpc = 0; lpc < data->nfields; lpc++) {
		if(data->types[lpc] == FT_STRUCT) {
			has_children = TRUE;
			break;
		}
	}

	printed = sprintf(buffer, "%s>", has_children==0?"/":"");
	update_buffer_head(buffer, printed);
	cl_log(log_level, "%s%s", prefix?prefix:"", print_buffer);
	buffer = print_buffer;
	
	if(has_children == FALSE) {
		return 0;
	}
	
	for (lpc = 0; lpc < data->nfields; lpc++) {
		if(data->types[lpc] != FT_STRUCT) {
			continue;
		} else if(0 > struct_display_as_xml(
				  log_level, depth+1, data->values[lpc],
				  prefix, formatted)) {
			return -1;
		}
	}

	if(formatted) {
		printed = struct_display_print_spaces(buffer, depth);
		update_buffer_head(buffer, printed);
	}
	cl_log(log_level, "%s%s</%s>", prefix?prefix:"", print_buffer, name);

	return 0;
}




static int 
liststring(GList* list, char* buf, int maxlen)
{
	char* p = buf;
	char* maxp = buf + maxlen;
	size_t i;
	
	for ( i = 0; i < g_list_length(list); i++){
		char* element = g_list_nth_data(list, i);
		if (element == NULL) {
			cl_log(LOG_ERR, "%luth element is NULL "
			,	(unsigned long)i);
			return HA_FAIL;
		} else{
			if (i == 0){
				p += sprintf(p,"%s",element);
			}else{
				p += sprintf(p," %s",element);
			}
			
		}
		if ( p > maxp){
			cl_log(LOG_ERR, "buffer overflow");
			return HA_FAIL;
		}
		
	}
	
	return HA_OK;
}

static void
list_display(int log_level, int seq, char* name, void* value, int vlen)
{
	GList* list;
	char buf[MAXLENGTH];
	
	HA_MSG_ASSERT(name);
	HA_MSG_ASSERT(value);

	list = value;

	if (liststring(list, buf, MAXLENGTH) != HA_OK){
		cl_log(LOG_ERR, "liststring error");
		return;
	}
	cl_log(log_level, "MSG[%d] :[(%s)%s=%s]",
	       seq, FT_strings[FT_LIST],
	       name, buf);			
	
	return ;
	
}


/*
 * This function changes each new line in the input string
 * into a special symbol, or the other way around
 */

int
convert_nl_sym(char* s, int len, char sym, int direction)
{
	int	i;

	if (direction != NL_TO_SYM && direction != SYM_TO_NL){
		cl_log(LOG_ERR, "convert_nl_sym(): direction not defined!");
		return(HA_FAIL);
	}


	for (i = 0; i < len && s[i] != EOS; i++){
		
		switch(direction){
		case NL_TO_SYM :
			if (s[i] == '\n'){
				s[i] = sym;
				break;
			}

			if (s[i] == sym){
				cl_log(LOG_ERR
				, "convert_nl_sym(): special symbol \'0x%x\' (%c) found"
				" in string at %d (len=%d)", s[i], s[i], i, len);
				i -= 10;
				if(i < 0) {
					i = 0;
				}
				cl_log(LOG_ERR, "convert_nl_sym(): %s", s + i);
				return(HA_FAIL);
			}

			break;

		case SYM_TO_NL:
						
			if (s[i] == sym){
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


/*
 * This function changes each new line in the input string
 * into a special symbol, or the other way around
 */

static int
convert(char* s, int len, int depth, int direction)
{
	
	if (direction != NL_TO_SYM && direction != SYM_TO_NL){
		cl_log(LOG_ERR, "convert(): direction not defined!");
		return(HA_FAIL);
	}
	
	
	if (depth >= MAXDEPTH ){
		cl_log(LOG_ERR, "convert(): MAXDEPTH exceeded: %d", depth);
		return(HA_FAIL);
	}
	
	return convert_nl_sym(s, len, SPECIAL_SYMS[depth], direction);
}




static int 
string_stringlen(size_t namlen, size_t vallen, const void* value)
{
	
	HA_MSG_ASSERT(value);
/* 	HA_MSG_ASSERT( vallen == strlen(value)); */
	return namlen + vallen + 2;
}

static int
binary_netstringlen(size_t namlen, size_t vallen, const void* value)
{
	int	length;
	
	HA_MSG_ASSERT(value);
	
	length = 3 + namlen + 1 + vallen;
	
	return length;
}


static int 
string_netstringlen(size_t namlen, size_t vallen, const void* value)
{
	HA_MSG_ASSERT(value);
	HA_MSG_ASSERT( vallen == strlen(value));
	
	return binary_netstringlen(namlen, vallen, value);
}


static int
binary_stringlen(size_t namlen, size_t vallen, const void* value)
{
	HA_MSG_ASSERT(value);

	return namlen + B64_stringlen(vallen)  + 2 + 3;
	/*overhead 3 is for type*/	
}





int
struct_stringlen(size_t namlen, size_t vallen, const void* value)
{
	const struct ha_msg* childmsg;
	
	HA_MSG_ASSERT(value);
	
	(void)vallen;
	childmsg = (const struct ha_msg*)value;
	
	return namlen +2 + 3 + get_stringlen(childmsg); 
	/*overhead 3 is for type*/
}

int
struct_netstringlen(size_t namlen, size_t vallen, const void* value)
{

	int ret;
	const struct ha_msg* childmsg;
	int len;

	HA_MSG_ASSERT(value);	

	(void)vallen;
	childmsg = (const struct ha_msg*)value;
	
	len = get_netstringlen(childmsg);

	ret = 3 + namlen + 1 + len;

	return ret;
	
}


static int
list_stringlen(size_t namlen, size_t vallen, const void* value)
{
	(void)value;
	return namlen + vallen + 2 + 3;	
	/*overhead 3 is for type (FT_STRUCT)*/
}

static int
list_netstringlen(size_t namlen, size_t vallen, const void* value)
{
	int ret;
	const GList* list;
	
	list = (const GList*)value;
	
	ret =  3 + namlen + 1 + string_list_pack_length(list);
	
	return ret;

}

static int 
add_binary_field(struct ha_msg* msg, char* name, size_t namelen,
		 void* value, size_t vallen, int depth)
{

	int next;

	if ( !msg || !name || !value
	     || depth < 0){
		cl_log(LOG_ERR, "add_binary_field:"
		       " invalid input argument");
		return HA_FAIL;
	}
		

	next = msg->nfields;
	msg->names[next] = name;
	msg->nlens[next] = namelen;
	msg->values[next] = value;
	msg->vlens[next] = vallen;       	
	msg->types[next] = FT_BINARY;
	msg->nfields++;	
	
	return HA_OK;
}


static int 
add_struct_field(struct ha_msg* msg, char* name, size_t namelen,
		 void* value, size_t vallen, int depth)
{	
	int next;

	if ( !msg || !name || !value
	     || depth < 0){
		cl_log(LOG_ERR, "add_struct_field:"
		       " invalid input argument");
		return HA_FAIL;
	}
	
	next = msg->nfields;
	msg->names[next] = name;
	msg->nlens[next] = namelen;
	msg->values[next] = value;
	msg->vlens[next] = vallen;			
	msg->types[next] = FT_STRUCT;
	
	msg->nfields++;	
	
	return HA_OK;
}




static int 
add_list_field(struct ha_msg* msg, char* name, size_t namelen,
	       void* value, size_t vallen, int depth)
{
	int next;
	int j;
	GList* list = NULL;

	if ( !msg || !name || !value
	     || namelen <= 0 
	     || vallen <= 0
	     || depth < 0){
		cl_log(LOG_ERR, "add_list_field:"
		       " invalid input argument");
		return HA_FAIL;
	}
	
	
	for (j=0; j < msg->nfields; ++j) {
		if (strcmp(name, msg->names[j]) == 0) {
			break;
		}
	}
	
	if ( j >= msg->nfields){
		list = (GList*)value;

		next = msg->nfields;
		msg->names[next] = name;
		msg->nlens[next] = namelen;
		msg->values[next] = value;
		msg->vlens[next] =  vallen;
		msg->types[next] = FT_LIST;
		msg->nfields++;
		
	}  else if(  msg->types[j] == FT_LIST ){

		GList* oldlist = (GList*) msg->values[j];
		int listlen;
		size_t i; 
		
		for ( i =0; i < g_list_length((GList*)value); i++){
			list = g_list_append(oldlist, g_list_nth_data((GList*)value, i));
		}
		if (list == NULL){
			cl_log(LOG_ERR, "add_list_field:"
			       " g_list_append() failed");
			return HA_FAIL;
		}
		
		listlen = string_list_pack_length(list);		
		
		msg->values[j] = list;
		msg->vlens[j] = listlen;
		g_list_free((GList*)value); /*we don't free each element
					      because they are used in new list*/
		free(name); /* this name is no longer necessary
			       because msg->names[j] is reused */
		
	} else { 
		cl_log(LOG_ERR, "field already exists "
		       "with differnt type=%d", msg->types[j]);
		return (HA_FAIL);
	}
		
	return HA_OK;
}


static int 
add_compress_field(struct ha_msg* msg, char* name, size_t namelen,
		 void* value, size_t vallen, int depth)
{

	int next;

	if ( !msg || !name || !value
	     || depth < 0){
		cl_log(LOG_ERR, "add_binary_field:"
		       " invalid input argument");
		return HA_FAIL;
	}
		

	next = msg->nfields;
	msg->names[next] = name;
	msg->nlens[next] = namelen;
	msg->values[next] = value;
	msg->vlens[next] = vallen;
	msg->types[next] = FT_COMPRESS;
	msg->nfields++;	
	
	return HA_OK;
}




static int 
add_uncompress_field(struct ha_msg* msg, char* name, size_t namelen,
		 void* value, size_t vallen, int depth)
{	
	int next;

	if ( !msg || !name || !value
	     || depth < 0){
		cl_log(LOG_ERR, "add_struct_field:"
		       " invalid input argument");
		return HA_FAIL;
	}
	
	next = msg->nfields;
	msg->names[next] = name;
	msg->nlens[next] = namelen;
	msg->values[next] = value;
	msg->vlens[next] = vallen;			
	msg->types[next] = FT_UNCOMPRESS;
	
	msg->nfields++;	
	
	return HA_OK;
}



/*print a string to a string,
  pretty simple one :)
*/
static int
str2string(char* buf, char* maxp, void* value, size_t len, int depth)
{
	char* s =  value;
	char* p = buf;
	(void)maxp;
	(void)depth;
	
	if (buf + len > maxp){
		cl_log(LOG_ERR, "%s: out of boundary",
		       __FUNCTION__);
		return -1;
	}

	if ( strlen(s) != len){
		cl_log(LOG_ERR, "str2string:"
		       "the input len != string length");
		return -1;
	}
	
	strcat(buf, s);
	while(*p != '\0'){
		if (*p == '\n'){
			*p = SPECIAL_SYM;
		}
		p++;
	}

	return len;
	
}

/*print a binary value to a string using base64
  library 
*/

static int
binary2string(char* buf, char* maxp, void* value, size_t len, int depth)
{
	int baselen;
	int truelen = 0;
	
	(void)depth;
	baselen = B64_stringlen(len) + 1;
	
	if ( buf + baselen > maxp){
		cl_log(LOG_ERR, "binary2string: out of bounary");
		return -1;
	}
	
	truelen = binary_to_base64(value, len, buf, baselen);
	
	return truelen;
}

/*print a struct(ha_msg) to a string	      
  @depth denotes the number of recursion
*/

static int
struct2string(char* buf, char* maxp, void* value, size_t len, int depth)
{

	struct ha_msg* msg = value;
	int	baselen = get_stringlen(msg);
	
	(void)len;

	if ( buf + baselen > maxp){
		cl_log(LOG_ERR, "struct2string: not enough buffer"
		       "for the struct to generate a string");
		return -1;
	}

	if (msg2string_buf(msg, buf ,baselen,depth + 1, NEEDHEAD)
	    != HA_OK){
		
		cl_log(LOG_ERR
		       , "struct2string(): msg2string_buf for"
		       " child message failed");		
		return -1;
		
	}
	
	if (convert(buf, baselen, depth, NL_TO_SYM) != HA_OK){		
		cl_log(LOG_ERR , "struct2string(): convert failed");		
		return -1;		
	}
	
	return strlen(buf);
}




/* print a list to a string
 */

static int
list2string(char* buf, char* maxp, void* value, size_t len, int depth)
{
	int listlen;
	GList* list = (GList*) value;

	(void)len;
	(void)depth;
	listlen = string_list_pack(list , buf, maxp);			
	if (listlen == 0){
		cl_log(LOG_ERR, "list2string():"
		       "string_list_pack() failed");
		return -1;
	}
	
	return listlen;	
	
}


static int
string2str(void* value, size_t len, int depth, void** nv, size_t* nlen )
{
	if (!value  || !nv || !nlen || depth < 0){
		cl_log(LOG_ERR, "string2str:invalid input");
		return HA_FAIL;
	}
	
	if (convert_nl_sym(value, len, SPECIAL_SYM, SYM_TO_NL) !=  HA_OK){
		cl_log(LOG_ERR, "string2str:convert_nl_sym"
		       "from symbol to new line failed");
		return HA_FAIL;
	}
	*nv = value;
	*nlen = len;
	
	return HA_OK;
}

static int
string2binary(void* value, size_t len, int depth, void** nv, size_t* nlen)
{
	char	tmpbuf[MAXLINE];
	char*	buf = NULL;
	int	buf_malloced = 0;
	int	ret = HA_FAIL;
	if (len > MAXLINE){
		buf = malloc(len);
		if (buf == NULL){
			cl_log(LOG_ERR, "%s: malloc failed",
			       __FUNCTION__);
			goto out;
		}
		buf_malloced = 1;
	}else {
		buf = &tmpbuf[0];		
	}
	
	if (value == NULL && len == 0){
		*nv = NULL;
		*nlen = 0;
		ret = HA_OK;
		goto out;
	}

	if ( !value || !nv || depth < 0){
		cl_log(LOG_ERR, "string2binary:invalid input");
		ret = HA_FAIL;
		goto out;
	}
	
	memcpy(buf, value, len);
	*nlen = base64_to_binary(buf, len, value, len);				
	
	*nv = value;
	ret = HA_OK;
 out:
	if (buf_malloced && buf){
		free(buf);
	}
	return ret;
}

static int
string2struct(void* value, size_t vallen, int depth, void** nv, size_t* nlen)
{
	
	struct ha_msg	*tmpmsg;

	if (!value || !nv || depth < 0){
		cl_log(LOG_ERR, "string2struct:invalid input");
		return HA_FAIL;
	}
	
	
	if (convert(value, vallen, depth,SYM_TO_NL) != HA_OK){
		cl_log(LOG_ERR
		       ,	"ha_msg_addraw_ll(): convert failed");
		return(HA_FAIL);
	}
	
	tmpmsg = string2msg_ll(value, vallen,depth + 1, 0);
	if (tmpmsg == NULL){
		cl_log(LOG_ERR
		       ,	"string2struct()"
		       ": string2msg_ll failed");
		return(HA_FAIL);
	}
	free(value);
	*nv = tmpmsg;
	*nlen = 0;
	
	return HA_OK;

}

static int
string2list(void* value, size_t vallen, int depth, void** nv, size_t* nlen)
{
	GList*	list;
	
	if (!value  || !nv || !nlen || depth < 0){
		cl_log(LOG_ERR, "string2struct:invalid input");
		return HA_FAIL;
	}	
	
	list = string_list_unpack(value, vallen);
	if (list == NULL){
		cl_log(LOG_ERR, "ha_msg_addraw_ll():"
		       "unpack_string_list failed: %s", (char*)value);
		return(HA_FAIL);
	}
	free(value);
	
	*nv = (void*)list;
	*nlen = string_list_pack_length(list);
	
	return HA_OK;

}

static int
fields2netstring(char* sp, char* smax, char* name, size_t nlen,
		 void* value, size_t vallen, int type, size_t* comlen)
{
	size_t fieldlen;
	size_t slen;
	int ret = HA_OK;
	char* sp_save = sp;
	char* tmpsp;

	fieldlen = fieldtypefuncs[type].netstringlen(nlen, vallen, value);
	/* this check seems to be superfluous because of the next one
	if (fieldlen > MAXMSG){
		cl_log(LOG_INFO, "%s: field too big(%d)", __FUNCTION__, (int)fieldlen);
		return HA_FAIL;
	}
	*/
	tmpsp = sp + netstring_extra(fieldlen);
	if (tmpsp > smax){
		cl_log(LOG_ERR, "%s: memory out of boundary, tmpsp=%p, smax=%p", 
		       __FUNCTION__, tmpsp, smax);
		return HA_FAIL;
	}
	sp += sprintf(sp , "%d:(%d)%s=", (int)fieldlen, type, name);
	switch (type){

	case FT_STRING:
	case FT_BINARY:
	case FT_COMPRESS:
		memcpy(sp, value, vallen);
		slen = vallen;
		break;

	case FT_UNCOMPRESS:
	case FT_STRUCT:
		{
			struct ha_msg* msg = (struct ha_msg*) value;
			/* infinite recursion? Must say that I got lost at
			 * this point
			 */
			ret = msg2netstring_buf(msg, sp,get_netstringlen(msg),
						&slen);
			break;
		}
	case FT_LIST:
		{

			char buf[MAXLENGTH];
			GList* list = NULL;
			int tmplen;
			
			list = (GList*) value;
			
			tmplen = string_list_pack_length(list);
			if (tmplen >= MAXLENGTH){
				cl_log(LOG_ERR,
				       "string list length exceeds limit");
				return(HA_FAIL);
			}
			
			if (string_list_pack(list, buf, buf + MAXLENGTH) 
			    != tmplen ){
				cl_log(LOG_ERR, 
				       "packing string list return wrong length");
				return(HA_FAIL);
			}
			
			
			memcpy(sp, buf, tmplen);
			slen = tmplen;
			ret = HA_OK;
			break;
		}
		
	default:
		ret = HA_FAIL;
		cl_log(LOG_ERR, "%s: Wrong type (%d)", __FUNCTION__,type);
	}	

	if (ret == HA_FAIL){
		return ret;
	}
	
	sp +=slen;
	*sp++ = ',';
	*comlen = sp - sp_save;
	
	return HA_OK;
	
	
}


static int
netstring2string(const void* value, size_t vlen, void** retvalue, size_t* ret_vlen)
{
	char* dupvalue;
	
	if (value == NULL && vlen == 0){
		*retvalue = NULL;
		*ret_vlen = 0;
		return HA_OK;
	}

	if ( !value || !retvalue || !ret_vlen){
		cl_log(LOG_ERR, " netstring2string:"
		       "invalid input arguments");
		return HA_FAIL;
	}
	
	dupvalue = binary_dup(value, vlen);
	if (!dupvalue){
		cl_log(LOG_ERR, "netstring2string:"
		       "duplicating value failed");
		return HA_FAIL;
	}
	
	*retvalue = dupvalue;
	*ret_vlen = vlen;
	
	return HA_OK;
}

static int
netstring2binary(const void* value, size_t vlen, void** retvalue, size_t* ret_vlen)
{
	return netstring2string(value, vlen, retvalue, ret_vlen);
	
}

static int
netstring2struct(const void* value, size_t vlen, void** retvalue, size_t* ret_vlen)
{
	struct ha_msg* msg;
	
	if ( !value || !retvalue || !ret_vlen){
		cl_log(LOG_ERR, " netstring2struct:"
		       "invalid input arguments");
		return HA_FAIL;
	}	
	
	msg =  netstring2msg(value, vlen, 0);
	if (!msg){
		cl_log(LOG_ERR, "netstring2struct:"
		       "netstring2msg failed");
		return HA_FAIL;
	}
	
	*retvalue =(void* ) msg;
	*ret_vlen = 0;
	
	return HA_OK;
	
}

static int
netstring2list(const void* value, size_t vlen, void** retvalue, size_t* ret_vlen)
{	
	GList* list;
	
	if ( !value || !retvalue || !ret_vlen){
		cl_log(LOG_ERR, " netstring2struct:"
		       "invalid input arguments");
		return HA_FAIL;
	}	
	
	
	list = string_list_unpack(value, vlen);
	if (list == NULL){
		cl_log(LOG_ERR, "netstring2list: unpacking string list failed");
		cl_log(LOG_INFO, "thisbuf=%s", (const char*)value);
		return HA_FAIL;
	}
	*retvalue = (void*)list;
	
	*ret_vlen = string_list_pack_length(list);
	
	return HA_OK;
	
}





static int 
add_string_field(struct ha_msg* msg, char* name, size_t namelen,
		 void* value, size_t vallen, int depth)
{
	
	size_t	internal_type;
	unsigned long	tmptype;
	char	*cp_name = NULL;
	size_t	cp_namelen;
	size_t	cp_vallen;
	void	*cp_value = NULL;
	int	next;

	if ( !msg || !name || !value
	     || namelen <= 0 
	     || depth < 0){
		cl_log(LOG_ERR, "add_string_field:"
		       " invalid input argument");
		return HA_FAIL;
	}
	

	
	internal_type = FT_STRING;
	if (name[0] == '('){

		int	nlo = 3; /*name length overhead */
		if (name[2] != ')'){
			if (!cl_msg_quiet_fmterr) {
				cl_log(LOG_ERR
				       , "ha_msg_addraw_ll(): no closing parentheses");
			}
			return(HA_FAIL);
		}
		tmptype = name[1] - '0';
		if (tmptype < 0 || tmptype > 9) {
			cl_log(LOG_ERR
			       ,	"ha_msg_addraw_ll(): not a number.");
			return(HA_FAIL);
		}

		internal_type = tmptype;
		
		if (internal_type ==  FT_STRING){
			cl_log(LOG_ERR
			       ,	"ha_msg_addraw_ll(): wrong type");
			return(HA_FAIL);
		}

		cp_name = name;
		cp_namelen = namelen - nlo ;
		memmove(cp_name, name + nlo, namelen - nlo);
		cp_name[namelen - nlo] = EOS;
	}else {
		cp_name = name;
		cp_namelen = namelen;	
		
	}
	
	if(internal_type  < DIMOF(fieldtypefuncs)){
		int (*stringtofield)(void*, size_t, int depth, void**, size_t* );
		int (*fieldstringlen)( size_t, size_t, const void*);

		stringtofield= fieldtypefuncs[internal_type].stringtofield;
		
		if (!stringtofield || stringtofield(value, vallen, depth, &cp_value, &cp_vallen) != HA_OK){
			cl_log(LOG_ERR, "add_string_field: stringtofield failed");
			return HA_FAIL;
		}
		
		fieldstringlen = fieldtypefuncs[internal_type].stringlen;
		if (!fieldstringlen ||
					fieldstringlen(cp_namelen, cp_vallen, cp_value) <= 0 ){
			
			cl_log(LOG_ERR, "add_string_field: stringlen failed");
			return HA_FAIL;
		}
		
	} else {
		cl_log(LOG_ERR, "add_string_field():"
		       " wrong type %lu", (unsigned long)internal_type);
		return HA_FAIL;
	}
	
	
	next = msg->nfields;
	msg->values[next] = cp_value;
	msg->vlens[next] = cp_vallen;
	msg->names[next] = cp_name;
	msg->nlens[next] = cp_namelen;
	msg->types[next] = internal_type;
	msg->nfields++;
	
	return HA_OK;
	
}

static int
uncompress2compress(struct ha_msg* msg, int index)
{
	char*	buf;
	size_t	buflen = MAXMSG;
	int	rc = HA_FAIL;

	buf = malloc(buflen);
	if (!buf) {
		cl_log(LOG_ERR, "%s: failed to allocate buffer",
		       __FUNCTION__);
		goto err;
	}

	if (msg->types[index] != FT_UNCOMPRESS){
		cl_log(LOG_ERR, "%s: the %dth field is not FT_UNCOMPRESS type",
		       __FUNCTION__, index);
		goto err;
	}
	

	if (cl_compress_field(msg, index, buf, &buflen) != HA_OK){
		cl_log(LOG_ERR, "%s: compressing %dth field failed", __FUNCTION__, index);
		goto err;
	}
	
	rc = cl_msg_replace(msg, index, buf, buflen, FT_COMPRESS);

err:
	if (buf) {
		free(buf);
	}

	return rc;
}

static int
compress2uncompress(struct ha_msg* msg, int index)
{
	char		*buf = NULL;
	size_t		buflen = MAXUNCOMPRESSED;	
	struct ha_msg*  msgfield;
	int 		err = HA_FAIL;

	buf = malloc(buflen);
	
	if (!buf) {
		cl_log(LOG_ERR, "%s: allocating buffer for uncompression failed",
		       __FUNCTION__);
		goto out;
	}

	if (cl_decompress_field(msg, index, buf, &buflen) != HA_OK){
		cl_log(LOG_ERR, "%s: compress field failed",
		       __FUNCTION__);
		goto out;
	}
	
	msgfield = wirefmt2msg(buf, buflen, 0);
	if (msgfield == NULL){
		cl_log(LOG_ERR, "%s: wirefmt to msg failed",
		       __FUNCTION__);
		goto out;
	}
	
	err = cl_msg_replace(msg, index, (char*)msgfield, 0, FT_UNCOMPRESS);

	ha_msg_del(msgfield);

out:
	if (buf) {
		free(buf);
	}

	return err;
}

/*
 * string	FT_STRING
 *		string is the basic type used in heartbeat, it is used for printable ascii value
 *
 * binary	FT_BINARY
 *		binary means the value can be any binary value, including non-printable ascii value
 *
 * struct	FT_STRUCT
 *		struct means the value is also an ha_msg (actually it is a pointer to an ha message)
 *
 * list		FT_LIST
 *		LIST means the value is a GList. Right now we only suppport a Glist of strings
 *
 * compress	FT_COMPRESS
 *		This field and the next one(FT_UNCOMPRESS) is designed to optimize compression in message
 *		(see cl_compression.c for more about compression). This field is similar to the binary field.
 *		It stores a compressed field, which will be an ha_msg if uncompressed. Most of time this field
 *		act like a binary field until compress2uncompress() is called. That function will be called 
 *		when someone calls cl_get_struct() to get this field value. After that this field is converted
 *		to a new type FT_UNCOMPRESS
 *
 * uncompress	FT_UNCOMPRESS
 *		As said above, this field is used to optimize compression. This field is similar to the struct 
 *		field. It's value is a pointer to an ha_msg. This field will be converted to a new type FT_COMPRESS
 *		when msg2wirefmt() is called, where uncompress2compress is called to do the field compression
 */

struct fieldtypefuncs_s fieldtypefuncs[NUM_MSG_TYPES]=
	{ {string_memfree, string_dup, string_display, add_string_field, 
	   string_stringlen,string_netstringlen, str2string,fields2netstring, 
	   string2str, netstring2string, NULL, NULL},
	  
	  {binary_memfree, binary_dup, binary_display, add_binary_field,
	   binary_stringlen,binary_netstringlen, binary2string,fields2netstring, 
	   string2binary, netstring2binary, NULL, NULL},
	  
	  {struct_memfree, struct_dup, struct_display, add_struct_field, 
	   struct_stringlen, struct_netstringlen, struct2string, fields2netstring, \
	   string2struct, netstring2struct, NULL, NULL},
	  
	  {list_memfree, list_dup, list_display, add_list_field, 
	   list_stringlen, list_netstringlen, list2string, fields2netstring, 
	   string2list, netstring2list, NULL, NULL},
	  
	  {binary_memfree, binary_dup, compress_display, add_compress_field,
	   binary_stringlen,binary_netstringlen, binary2string ,fields2netstring, 
	   string2binary , netstring2binary, NULL, compress2uncompress}, /*FT_COMPRESS*/
	  
	  {struct_memfree, struct_dup, uncompress_display, add_uncompress_field, 
	   struct_stringlen, struct_netstringlen, NULL , fields2netstring, 
	   NULL , netstring2struct, uncompress2compress, NULL}, /*FT_UNCOMPRSS*/
	};


