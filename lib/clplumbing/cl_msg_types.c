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

#define		NL_TO_SYM	0
#define		SYM_TO_NL	1

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

extern const char* FT_strings[];


struct ha_msg* string2msg_ll(const char*, size_t, int, int);
int compose_netstring(char*, const char*, const char*, size_t, size_t*);
int msg2netstring_buf(const struct ha_msg*, char*, size_t, size_t*);


static int
intlen(int x)
{
	char	buf[20];
	return snprintf(buf, sizeof(buf), "%d", x);
}


/*
  compute the total size of the resulted string
  if the string list is to be converted
  
*/
size_t
string_list_pack_length(const GList* _list)
{
	int i;
	GList* list = NULL;
	size_t total_length = 0;
	
	memcpy(&list, &_list, sizeof(GList*));
	(void)list;

	if (list == NULL){
		cl_log(LOG_WARNING, "string_list_pack_length():"
		       "list is NULL");

		return 0;
	}
	for (i = 0; i < g_list_length(list) ; i++){
		
		char * element = g_list_nth_data(list, i);
		if (element == NULL){
			cl_log(LOG_ERR, "string_list_pack_length: "
			       "%dth element of the string list is NULL", i);
			return 0;
		}
		total_length += intlen(strlen(element)) + strlen(element) + 2;
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
	int i;
	char* p =  buf;

	for (i = 0; i < g_list_length(list) ; i++){
		
		char * element = g_list_nth_data(list, i);
		int element_len = strlen(element);
		if (element == NULL){
			cl_log(LOG_ERR, "string_list_pack: "
			       "%dth element of the string list is NULL", i);
			return 0;
		}
		p += sprintf(p, "%d:%s,", element_len,element);
		
		if (p >= maxp){
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
		
		buf = ha_malloc(len + 1);
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
		ha_free(value);
	}else {
		cl_log(LOG_ERR, "string_memfree: "
		       "value is NULL");
	}
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
binary_dup(const void* value, size_t len){
	
	char* dupvalue;
	
	if (!value || len < 0 ){
		cl_log(LOG_ERR,"binary_dup:"
		       "value is NULL or len < 0");
		return NULL ;
	}	
	
	dupvalue = ha_malloc(len + 1);
	if (dupvalue < 0){
		cl_log(LOG_ERR, "binary_dup:"
		       "ha_malloc failed");
		return NULL;
	}

	memcpy(dupvalue, value, len);

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
	
	if (!value || len < 0 ){
		cl_log(LOG_ERR,"struct_dup:"
		       "value is NULL or len < 0");
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
	int i;
	GList* newlist = NULL;
	GList* list;

	memcpy(&list, &_list, sizeof(GList*));

	for (i = 0; i < g_list_length(list); i++){
		char* dup_element = NULL;
		char* element = g_list_nth_data(list, i);
		int len;
		if (element == NULL){
			cl_log(LOG_WARNING, "list_cleanup:"
			       "element is NULL");
			continue;
		}

		len = strlen(element);
		dup_element= ha_malloc(len + 1);
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

	if (!value || len < 0 ){
		cl_log(LOG_ERR,"struct_dup:"
		       "value is NULL or len < 0");
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
string_display(int seq, char* name, void* value)
{
	HA_MSG_ASSERT(name);
	HA_MSG_ASSERT(value);
	cl_log(LOG_INFO, "MSG[%d] : [%s=%s]",
	       seq, name, (const char*)value);
	return;
}

static void
binary_display(int seq, char* name, void* value)
{
	HA_MSG_ASSERT(name);
	HA_MSG_ASSERT(value);
	cl_log(LOG_INFO, "MSG[%d] : [(%s)%s=%p]",
	       seq,	FT_strings[FT_BINARY],
	       name,	value);
}

static void
struct_display(int seq, char* name, void* value)
{
	HA_MSG_ASSERT(name);
	HA_MSG_ASSERT(value);	
	cl_log(LOG_INFO, "MSG[%d] : [(%s)%s=%p]",
	       seq,	FT_strings[FT_STRUCT],
	       name,	value);
	cl_log_message((struct ha_msg*) value);
	
}



static int 
liststring(GList* list, char* buf, int maxlen)
{
	char* p = buf;
	char* maxp = buf + maxlen;
	int i;
	
	for ( i = 0; i < g_list_length(list); i++){
		char* element = g_list_nth_data(list, i);
		if (element == NULL){
			cl_log(LOG_ERR, "%dth element is NULL ", i);
			return HA_FAIL;
		} else{
			if (i == 0){
				p += sprintf(p,"%s",element);
			}else{
				p += sprintf(p," %s",element);
			}
			
		}
		if ( p >= maxp){
			cl_log(LOG_ERR, "buffer overflow");
			return HA_FAIL;
		}
		
	}
	
	return HA_OK;
}

static void
list_display(int seq, char* name, void* value)
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
	cl_log(LOG_INFO, "MSG[%d] :[(%s)%s=%s]",
	       seq, FT_strings[FT_LIST],
	       name, buf);			
	
	return ;
	
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





static int 
string_stringlen(size_t namlen, size_t vallen, const void* value)
{
	
	HA_MSG_ASSERT(value);
	HA_MSG_ASSERT( vallen == strlen(value));
	
	return namlen + vallen+ 2;
}

static int 
string_netstringlen(size_t namlen, size_t vallen, const void* value)
{
	
	int length;
	
	HA_MSG_ASSERT(value);
	HA_MSG_ASSERT( vallen == strlen(value));

	length = intlen(namlen) + (namlen)
		+	intlen(vallen) + vallen + 4 ;
	length  += 4; /* for type*/
		
	return length;
}


static int
binary_stringlen(size_t namlen, size_t vallen, const void* value)
{
	HA_MSG_ASSERT(value);
	HA_MSG_ASSERT(vallen >=0  && namlen >= 0);
	
	return namlen + B64_stringlen(vallen)  + 2 + 3;
	/*overhead 3 is for type*/	
}

static int
binary_netstringlen(size_t namlen, size_t vallen, const void* value)
{
	int length;
 
	HA_MSG_ASSERT(value);
	HA_MSG_ASSERT(vallen >=0  && namlen >= 0);
	
	length = intlen(namlen) + (namlen)
		+	intlen(vallen) + vallen + 4 ;
	length  += 4; /* for type*/
	
	return length;	
}



static int
struct_stringlen(size_t namlen, size_t vallen, const void* value)
{
	const struct ha_msg* childmsg;
	
	HA_MSG_ASSERT(value);
	
	childmsg = (const struct ha_msg*)value;
	
	return namlen +2 + 3 + childmsg->stringlen; 
	/*overhead 3 is for type*/
}

static int
struct_netstringlen(size_t namlen, size_t vallen, const void* value)
{

	int ret;
	const struct ha_msg* childmsg;
	
	HA_MSG_ASSERT(value);	

	childmsg = (const struct ha_msg*)value;
	
	ret = intlen(namlen) + namlen + 2;
	/*for name*/
	ret += 4;
	/*for type*/
	ret += intlen(childmsg->netstringlen) + childmsg->netstringlen + 2;
	/*for child msg*/

	return ret;
	
}


/*  static int */
/*  struct_netstringlen(size_t namelen, size_t vallen, const void* value) */

	
/*  	return 0; */
/*  } */

static int
list_stringlen(size_t namlen, size_t vallen, const void* value)
{
	return namlen + vallen + 2 + 3;	
	/*overhead 3 is for type (FT_STRUCT)*/
}

static int
list_netstringlen(size_t namlen, size_t vallen, const void* value)
{
	int ret;

	ret =  intlen(namlen) + (namlen)
		+ intlen(vallen) 
		+ vallen +  4 ;
	
	ret += 4; /*for type*/
	
	return ret;

}

static int 
add_binary_field(struct ha_msg* msg, char* name, size_t namelen,
		 void* value, size_t vallen, int depth)
{

	int next;

	if ( !msg || !name || !value
	     || namelen <= 0 
	     || vallen <= 0
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
	
	msg->stringlen += binary_stringlen(namelen, vallen, value);
	
	msg->netstringlen += binary_netstringlen(namelen, vallen, value);

	msg->types[next] = FT_BINARY;
	msg->nfields++;	
	
	return HA_OK;
}


static int 
add_struct_field(struct ha_msg* msg, char* name, size_t namelen,
		 void* value, size_t vallen, int depth)
{	
	int next;
	struct ha_msg* childmsg;
	int stringlen_add;
	int netstringlen_add;

	if ( !msg || !name || !value
	     || namelen <= 0 
	     || vallen < 0
	     || depth < 0){
		cl_log(LOG_ERR, "add_struct_field:"
		       " invalid input argument");
		return HA_FAIL;
	}



	
	childmsg = (struct ha_msg*)value; 
	
	stringlen_add = struct_stringlen(namelen, vallen, value);	
	netstringlen_add =  struct_netstringlen(namelen, vallen, value);
	
	if (msg->stringlen + stringlen_add >= MAXMSG || 
	    msg->netstringlen + netstringlen_add >= MAXMSG){
		cl_log(LOG_ERR, "add_struct_field"
		       "msg too largge");
		return HA_FAIL;
	}
	

	next = msg->nfields;
	msg->names[next] = name;
	msg->nlens[next] = namelen;
	msg->values[next] = value;
	msg->vlens[next] = vallen;
	
	msg->stringlen += stringlen_add;
	msg->netstringlen +=  netstringlen_add;
	
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
	int stringlen_add;
	int netstringlen_add;
	
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
		int listlen;
		list = (GList*)value;

		listlen = string_list_pack_length(list);

		stringlen_add = list_stringlen(namelen,listlen , value);
		
		netstringlen_add = list_netstringlen(namelen, 
						     listlen, 
						     value);
		
		if (msg->stringlen + stringlen_add >= MAXMSG || 
		    msg->netstringlen + netstringlen_add >= MAXMSG){
			cl_log(LOG_ERR, "add_list_field"
			       "msg too large");
			return HA_FAIL;
		}		
		
		next = msg->nfields;
		msg->names[next] = name;
		msg->nlens[next] = namelen;
		msg->values[next] = value;
		msg->vlens[next] =  vallen;
		msg->types[next] = FT_LIST;
		msg->stringlen += stringlen_add;
		msg->netstringlen += netstringlen_add;
		msg->nfields++;
		
	}  else if(  msg->types[j] == FT_LIST ){

		GList* oldlist = (GList*) msg->values[j];
		int oldlistlen = string_list_pack_length(oldlist);
		int newlistlen;
		int i; 
		
		for ( i =0; i < g_list_length((GList*)value); i++){
			list = g_list_append(oldlist, g_list_nth_data((GList*)value, i));
		}
		if (list == NULL){
			cl_log(LOG_ERR, "add_list_field:"
			       " g_list_append() failed");
			return HA_FAIL;
		}
		
		newlistlen = string_list_pack_length(list);		
		
		stringlen_add = newlistlen - oldlistlen;
		netstringlen_add = intlen(newlistlen) + newlistlen
			- intlen(oldlistlen) - oldlistlen;		
		
		if (msg->stringlen+ stringlen_add >= MAXMSG 
		    || msg->netstringlen + netstringlen_add >= MAXMSG){
			cl_log(LOG_ERR, "ha_msg too big");
			list = g_list_remove(list, value);
			msg->values[j]=list;
			return HA_FAIL;
		} 
		
		
		msg->values[j] = list;
		msg->vlens[j] =  string_list_pack_length(list);
		msg->stringlen +=  stringlen_add;
		msg->netstringlen += netstringlen_add;
		g_list_free((GList*)value); /*we don't free each element
					      because they are used in new list*/
		
	} else { 
		cl_log(LOG_ERR, "field already exists "
		       "with differnt type=%d", msg->types[j]);
		return (HA_FAIL);
	}
		
	return HA_OK;
}



/*print a string to a string,
  pretty simple one :)
*/
static int
str2string(char* buf, char* maxp, void* value, size_t len, int depth)
{
	char* s =  value;
	
	if ( strlen(s) != len){
		cl_log(LOG_ERR, "str2string:"
		       "the input len(%ld) != string length(%ld)",
		       len, strlen(s));
		return 0;
	}
	
	strcat(buf, s);
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
	
	baselen = B64_stringlen(len) + 1;
	
	if ( buf + baselen >= maxp){
		cl_log(LOG_ERR, "binary2string: out of bounary");
		return 0;
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
	

	if ( buf + baselen > maxp){
		cl_log(LOG_ERR, "struct2string: not enough buffer"
		       "for the struct to generate a string");
		return 0;
	}

	if (msg2string_buf(msg, buf ,baselen,depth + 1, NEEDHEAD)
	    != HA_OK){
		
		cl_log(LOG_ERR
		       , "struct2string(): msg2string_buf for"
		       " child message failed");		
		return 0;
		
	}
	
	if (convert(buf, baselen, depth, NL_TO_SYM) != HA_OK){		
		cl_log(LOG_ERR , "struct2string(): convert failed");		
		return 0;		
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

	listlen = string_list_pack(list , buf, maxp);			
	if (listlen == 0){
		cl_log(LOG_ERR, "list2string():"
		       "string_list_pack() failed");
		return 0;
	}
	
	return listlen;	
	
}


static int
string2str(void* value, size_t len, int depth, void** nv, size_t* nlen )
{
	if (!value  || len <0 || !nv || !nlen || depth < 0){
		cl_log(LOG_ERR, "string2str:invalid input");
		return HA_FAIL;
	}

	*nv = value;
	*nlen = len;
	
	return HA_OK;
}

static int
string2binary(void* value, size_t len, int depth, void** nv, size_t* nlen )
{
	char	tmpbuf[MAXMSG];
	
	if (!value  || len <0 || !nv || !nlen || depth < 0){
		cl_log(LOG_ERR, "string2binary:invalid input");
		return HA_FAIL;
	}
	

	memcpy(tmpbuf, value,len);
	*nlen = base64_to_binary(tmpbuf, len, value, len);				

	if (*nlen <= 0){
		cl_log(LOG_ERR, "base64_to_binary() failed");
		return HA_FAIL;
	}
	
	*nv = value;
	
	return HA_OK;
}

static int
string2struct(void* value, size_t vallen, int depth, void** nv, size_t* nlen)
{
	
	struct ha_msg	*tmpmsg;

	if (!value  || vallen <0 || !nv || !nlen || depth < 0){
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
	ha_free(value);
	*nv = tmpmsg;
	*nlen = 0;
	
	return HA_OK;

}

static int
string2list(void* value, size_t vallen, int depth, void** nv, size_t* nlen)
{
	GList*	list;
	
	if (!value  || vallen <0 || !nv || !nlen || depth < 0){
		cl_log(LOG_ERR, "string2struct:invalid input");
		return HA_FAIL;
	}	
	
	list = string_list_unpack(value, vallen);
	if (list == NULL){
		cl_log(LOG_ERR, "ha_msg_addraw_ll():"
		       "unpack_string_list failed: %s", (char*)value);
		return(HA_FAIL);
	}
	ha_free(value);
	
	*nv = (void*)list;
	*nlen = string_list_pack_length(list);
	
	return HA_OK;

}


static int 
string2netstring(char* sp, char* smax, void* value, 
		 size_t vallen, size_t* comlen)
{
	
	if ( !sp || !smax || !value || vallen < 0 || !comlen ){
		cl_log(LOG_ERR, "string2netstring:"
		       "invalid input arguments");
		return HA_FAIL;
	}

	
	return compose_netstring(sp, smax, value, vallen, comlen);
	
}

static int
binary2netstring(char* sp, char* smax, void* value,
		 size_t vallen, size_t* comlen)
{
	
	return string2netstring(sp, smax, value, vallen, comlen);
	
}

static int
struct2netstring(char* sp, char* smax, void* value,
		 size_t vallen, size_t* comlen)
{
	size_t	tmplen;
	char	*sp_save = sp;
	struct ha_msg* msg;
	int llen;

	
	if ( !sp || !smax || !value || vallen < 0 || !comlen ){
		cl_log(LOG_ERR, "struct2netstring:"
		       "invalid input arguments");
		return HA_FAIL;
	}	
	
	msg = (struct ha_msg*) value;
	
	llen =  get_netstringlen(msg);

	sp += sprintf(sp, "%ld:", (long)llen);
	
	if (msg2netstring_buf(msg, sp, llen, &tmplen) != HA_OK){
		cl_log(LOG_ERR, "struct2netstring()"
		       ": msg2netstring_buf() failed");
		return(HA_FAIL);
	}
	
	sp +=llen;
	
	*sp++ = ',';
	*comlen = sp - sp_save;
	
	return HA_OK;
}


static int
list2netstring(char* sp, char* smax, void* value, 
	       size_t vallen, size_t* comlen)
{	
	size_t tmplen;
	GList* list = NULL;
	char buf[MAXLENGTH];
	
	if ( !sp || !smax || !value || vallen < 0 || !comlen ){
		cl_log(LOG_ERR, "list2netstring:"
		       "invalid input arguments");
		return HA_FAIL;
	}		
	
	list= (GList*) value;

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
	
	if (compose_netstring(sp, smax, buf, tmplen, comlen)
	    != HA_OK){
		cl_log(LOG_ERR,
		       "list2netstring: compose_netstring fails for"
		       " value");
		return(HA_FAIL);
	}
	
	return HA_OK;
	
}

static int
netstring2string(const void* value, size_t vlen, void** retvalue, size_t* ret_vlen)
{
	char* dupvalue;
	
	if ( !value || vlen < 0 || !retvalue || !ret_vlen){
		cl_log(LOG_ERR, " netstring2string:"
		       "invalid input arguments");
		return HA_FAIL;
	}
	
	dupvalue = string_dup(value, vlen);
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
	
	if ( !value || vlen < 0 || !retvalue || !ret_vlen){
		cl_log(LOG_ERR, " netstring2struct:"
		       "invalid input arguments");
		return HA_FAIL;
	}	
	
	msg =  netstring2msg(value, vlen, 1);
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
	
	if ( !value || vlen < 0 || !retvalue || !ret_vlen){
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
	
	int	internal_type;
	char	*cp_name = NULL;
	size_t	cp_namelen;
	size_t	cp_vallen;
	void	*cp_value = NULL;
	int	next;
	int	stringlen_add = 0 ;
	int	netstringlen_add =0;


	if ( !msg || !name || !value
	     || namelen <= 0 
	     || vallen <= 0
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
		sscanf(name + 1, "%d", &internal_type);
		
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
	
	if(internal_type  < sizeof(fieldtypefuncs) 
	   / sizeof(fieldtypefuncs[0])){					
		int (*stringtofield)(void*, size_t, int depth, void**, size_t* );
		int (*fieldstringlen)( size_t, size_t, const void*);
		int (*fieldnetstringlen)( size_t, size_t, const void*);

		stringtofield= fieldtypefuncs[internal_type].stringtofield;
		
		if (!stringtofield || stringtofield(value, vallen, depth, &cp_value, &cp_vallen) != HA_OK){
			cl_log(LOG_ERR, "add_string_field: stringtofield failed");
			return HA_FAIL;
		}
		
		fieldstringlen = fieldtypefuncs[internal_type].stringlen;
		if (!fieldstringlen || (stringlen_add = 
					fieldstringlen(cp_namelen, cp_vallen, cp_value)) <= 0 ){
			
			cl_log(LOG_ERR, "add_string_field: stringlen failed");
			return HA_FAIL;
		}
		
		fieldnetstringlen = fieldtypefuncs[internal_type].netstringlen;
		if (!fieldnetstringlen || (netstringlen_add = 
					   fieldnetstringlen(cp_namelen, cp_vallen, cp_value)) <= 0 ){
			
			cl_log(LOG_ERR, "add_string_field: netstringlen failed");
			return HA_FAIL;
		}		
	}
	
	
	if (msg->stringlen + stringlen_add >= MAXMSG ||
	    msg->netstringlen + netstringlen_add >= MAXMSG) {

		cl_log(LOG_ERR, "ha_msg_addraw_ll(): "
		       "cannot add name/value to ha_msg (value too big)");

		if (cp_value) {   
			if(internal_type  < sizeof(fieldtypefuncs) 
			   / sizeof(fieldtypefuncs[0])){			
				fieldtypefuncs[internal_type].memfree(cp_value);
			}
			cp_value = NULL;   
		}   
		if (cp_name) {   
			cl_free(cp_name);       cp_name = NULL;   
		} 		
		return(HA_FAIL);
	}
	
	
	next = msg->nfields;
	msg->values[next] = cp_value;
	msg->vlens[next] = cp_vallen;
	msg->names[next] = cp_name;
	msg->nlens[next] = cp_namelen;
	
	msg->stringlen += stringlen_add;	
	msg->netstringlen += netstringlen_add;
	
	msg->types[next] = internal_type;
	msg->nfields++;
	
	return HA_OK;
	
}



struct fieldtypefuncs_s fieldtypefuncs[4]=
	{ {string_memfree, string_dup, string_display, add_string_field, 
	   string_stringlen,string_netstringlen, str2string,string2netstring, string2str, netstring2string},
	  
	  {binary_memfree, binary_dup, binary_display, add_binary_field,
	   binary_stringlen,binary_netstringlen, binary2string,binary2netstring, string2binary, netstring2binary},
	  
	  {struct_memfree, struct_dup, struct_display, add_struct_field, 
	   struct_stringlen, struct_netstringlen, struct2string, struct2netstring, string2struct, netstring2struct},

	  {list_memfree, list_dup, list_display, add_list_field, 
	   list_stringlen, list_netstringlen, list2string, list2netstring, string2list, netstring2list},
	};


