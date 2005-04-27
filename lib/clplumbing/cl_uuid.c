
#include <portability.h>
#include <config.h>
#include <uuid/uuid.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <clplumbing/cl_uuid.h>
#include <clplumbing/cl_log.h>
#include <assert.h>

void
cl_uuid_copy(cl_uuid_t* dst, cl_uuid_t* src)
{
	if (dst == NULL || src == NULL){
		cl_log(LOG_ERR, "cl_uuid_copy: "
		       "wrong argument %s is NULL",
		       dst == NULL?"dst":"src");
		assert(0);
	}
	
	uuid_copy(dst->uuid, src->uuid);		
}

void 
cl_uuid_clear(cl_uuid_t* uu)
{
	if (uu == NULL){
		cl_log(LOG_ERR, "cl_uuid_clear: "
		       "wrong argument (uu is NULL)");
		assert(0);
	}
	
	uuid_clear(uu->uuid);
	
}

int 
cl_uuid_compare(cl_uuid_t* uu1, cl_uuid_t* uu2)
{
	if (uu1 == NULL || uu2 == NULL){
		cl_log(LOG_ERR, "cl_uuid_compare: "
		       " wrong argument (%s is NULL)",
		       uu1 == NULL?"uu1":"uu2");
		assert(0);
	}
	
	return uuid_compare(uu1->uuid, uu2->uuid);

}



void cl_uuid_generate(cl_uuid_t* out)
{
	if (out == NULL){
		cl_log(LOG_ERR, "cl_uuid_generate: "
		       " wrong argument (out is NULL)");
		assert(0);
	}

	uuid_generate(out->uuid);
	
}

int
cl_uuid_is_null(cl_uuid_t* uu)
{
	if (uu == NULL){
		cl_log(LOG_ERR, "cl_uuid_is_null: "
		       "wrong argument (uu is NULL)");
		assert(0);
	}
	
	return uuid_is_null(uu->uuid);
	
}

time_t 
cl_uuid_time(cl_uuid_t* uu, struct timeval *ret_tv)
{
	if (uu == NULL || ret_tv == NULL){

		cl_log(LOG_ERR, "cl_uuid_time: "
		       "wrong argument (%s is NULL)",
		       uu == NULL?"uu": "ret_tv");
		assert(0);
	}

	return uuid_time(uu->uuid, ret_tv);

}

int
cl_uuid_parse( char *in, cl_uuid_t* uu)
{
	if (in == NULL || uu == NULL){

		cl_log(LOG_ERR, "cl_uuid_parse: "
		       "wrong argument (%s is NULL)",
		       in == NULL? "in":"uu");
		assert(0);
	}
	
	return uuid_parse(in, uu->uuid);
}


void
cl_uuid_unparse(cl_uuid_t* uu, char *out){
	
	if (uu == NULL || out == NULL){
		cl_log(LOG_ERR, "cl_uuid_unparse: "
		       "wrong argument (%s is NULL)",
		       uu == NULL? "uu":"out");
		assert(0);
	}
	
	return uuid_unparse(uu->uuid, out);
}
