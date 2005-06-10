#ifndef _CL_UUID_H_
#define _CL_UUID_H_

#include <hb_uuid.h>

typedef struct cl_uuid_s{	
	uuid_t uuid;	
}cl_uuid_t;

void cl_uuid_copy(cl_uuid_t* dst, cl_uuid_t* src);
void cl_uuid_clear(cl_uuid_t* uu);
int cl_uuid_compare(cl_uuid_t* uu1, cl_uuid_t* uu2);
void cl_uuid_generate(cl_uuid_t* out);
int cl_uuid_is_null(cl_uuid_t* uu);
time_t cl_uuid_time(cl_uuid_t* uu, struct timeval *ret_tv);
int cl_uuid_parse( char *in, cl_uuid_t* uu);
void cl_uuid_unparse(cl_uuid_t* uu, char *out);


#endif


