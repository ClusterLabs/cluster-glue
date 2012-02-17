#define	MAX_PID_LEN 256
#define	MAX_PROC_NAME 256
#define	MAX_MSGTYPELEN 32
#define	MAX_CLASSNAMELEN 32
#define WARNINGTIME_IN_LIST 10000
#define OPTARGS		"skrhvmi:"
#define PID_FILE 	HA_VARRUNDIR"/lrmd.pid"
#define LRMD_COREDUMP_ROOT_DIR HA_COREDIR
#define APPHB_WARNTIME_FACTOR	3
#define APPHB_INTVL_DETLA 	30  /* Millisecond */

#define lrmd_log(priority, fmt...); \
		cl_log(priority, fmt);

#define lrmd_debug(priority, fmt...); \
        if ( debug_level >= 1 ) { \
                cl_log(priority, fmt); \
        }

#define lrmd_debug2(priority, fmt...); \
        if ( debug_level >= 2 ) { \
                cl_log(priority, fmt); \
        }

#define lrmd_debug3(priority, fmt...); \
        if ( debug_level >= 3 ) { \
                cl_log(priority, fmt); \
        }

#define	lrmd_nullcheck(p)	((p) ? (p) : "<null>")
#define	lrm_str(p)	(lrmd_nullcheck(p))

#define	CHECK_ALLOCATED(thing, name, result)				\
	if (!thing) {					\
		lrmd_log(LOG_ERR					\
		,	"%s: %s pointer 0x%lx is not allocated."	\
		,	__FUNCTION__, name, (unsigned long)thing);	\
		if (!in_alloc_dump) {					\
			in_alloc_dump = TRUE;				\
			dump_data_for_debug();				\
			in_alloc_dump = FALSE;				\
			return result;					\
		}							\
	}

#define CHECK_RETURN_OF_CREATE_LRM_RET	do {		\
	if (NULL == msg) {						\
		lrmd_log(LOG_ERR					\
		, 	"%s: cannot create a ret message with create_lrm_ret."	\
		, 	__FUNCTION__);					\
		return HA_FAIL;						\
	} \
} while(0)

#define LOG_FAILED_TO_GET_FIELD(field)					\
			lrmd_log(LOG_ERR				\
			,	"%s:%d: cannot get field %s from message." \
			,__FUNCTION__,__LINE__,field)

#define LOG_FAILED_TO_ADD_FIELD(field)					\
			lrmd_log(LOG_ERR				\
			,	"%s:%d: cannot add the field %s to a message." \
			,	__FUNCTION__				\
			,	__LINE__				\
			,	field)

/* NB: There's a return in these macros, hence the names */
#define return_on_no_int_value(msg,fld,i) do { \
	if (HA_OK != ha_msg_value_int(msg,fld,i)) { \
		LOG_FAILED_TO_GET_FIELD(fld); \
		return HA_FAIL; \
	} \
} while(0)
#define return_on_no_value(msg,fld,v) do { \
	v = ha_msg_value(msg,fld); \
	if (!v) { \
		LOG_FAILED_TO_GET_FIELD(fld); \
		return HA_FAIL; \
	} \
} while(0)

#define LRMD_APPHB_HB				\
        if (reg_to_apphb == TRUE) {		\
                if (apphb_hb() != 0) {		\
                        reg_to_apphb = FALSE;	\
                }				\
        }

#define tm2age(tm) \
	(cmp_longclock(tm, zero_longclock) <= 0) ? \
		0 : longclockto_ms(sub_longclock(now, tm))
#define tm2unix(tm) \
	(time(NULL)-(tm2age(tm)+999)/1000)

/*
 * The basic objects in our world:
 *
 *	lrmd_client_t:
 *	Client - a process which has connected to us for service.
 *
 *	lrmd_rsc_t:
 *	Resource - an abstract HA cluster resource implemented by a
 *		resource agent through our RA plugins
 *		It has two list of operations (lrmd_op_t) associated with it
 *			op_list - operations to be run as soon as they're ready
 *			repeat_op_list - operations to be run later
 *		It maintains the following tracking structures:
 *			last_op_done   Last operation performed on this resource
 *			last_op_table  Last operations of each type done per client
 *
 *	lrmd_op_t:
 *	Resource operation - an operation on a resource -- requested
 *	by a client.
 *
 *	ProcTrack - tracks a currently running resource operation.
 *		It points back to the lrmd_op_t that started it.
 *
 * Global structures containing these things:
 *
 *	clients - a hash table of all (currently connected) clients
 *
 *	resources - a hash table of all (currently configured) resources
 *
 *	Proctrack keeps its own private data structures to keep track of
 *	child processes that it created.  They in turn point to the
 *	lrmd_op_t objects that caused us to fork the child process.
 *
 *
 */

/*
 * Recognized privilege levels
 */

#define PRIV_ADMIN 8 /* ADMIN_UIDS are administrators */
#define ADMIN_UIDS "0,"HA_CCMUSER
#define ADMIN_GIDS "0,"HA_APIGROUP /* unused */

typedef struct
{
	char*		app_name;
	pid_t		pid;
	gid_t		gid;
	uid_t		uid;

	IPC_Channel*	ch_cmd;
	IPC_Channel*	ch_cbk;

	GCHSource*	g_src;
	GCHSource*	g_src_cbk;
	char		lastrequest[MAX_MSGTYPELEN];
	time_t		lastreqstart;
	time_t		lastreqend;
	time_t		lastrcsent;
	int		priv_lvl; /* client privilege level (depends on uid/gid) */
}lrmd_client_t;

typedef struct lrmd_rsc lrmd_rsc_t;
typedef struct lrmd_op	lrmd_op_t;
typedef struct ra_pipe_op  ra_pipe_op_t;

#define RSC_REMOVAL_PENDING 1
#define RSC_FLUSHING_OPS 2
#define rsc_frozen(r) \
	((r)->state==RSC_REMOVAL_PENDING || (r)->state==RSC_FLUSHING_OPS)
#define rsc_removal_pending(r) \
	((r)->state==RSC_REMOVAL_PENDING)
#define set_rsc_removal_pending(r) \
	(r)->state = RSC_REMOVAL_PENDING
#define set_rsc_flushing_ops(r) \
	(r)->state = RSC_FLUSHING_OPS
#define rsc_reset_state(r) (r)->state = 0
/* log messages for repeating ops (monitor) once an hour */
#define LOGMSG_INTERVAL (60*60)
#define is_logmsg_due(op) \
	(longclockto_ms(sub_longclock(time_longclock(), op->t_lastlogmsg))/1000 >= \
		(unsigned long)LOGMSG_INTERVAL)
#define probe_str(op,op_type) \
	((op && !op->interval && !strcmp(op_type,"monitor")) ? "probe" : op_type)
/* exclude stonith class from child count */
#define no_child_count(rsc) \
	(strcmp((rsc)->class,"stonith") == 0)

struct lrmd_rsc
{
	char*		id;		/* Unique resource identifier	*/
	char*		type;		/* 				*/
	char*		class;		/*				*/
	char*		provider;	/* Resource provider (optional)	*/
	GHashTable* 	params;		/* Parameters to this resource	*/
					/* as name/value pairs		*/
	GList*		op_list;	/* Queue of operations to run	*/
	GList*		repeat_op_list;	/* Unordered list of repeating	*/
					/* ops They will run later	*/
	GHashTable*	last_op_table;	/* Last operation of each type	*/
	lrmd_op_t*	last_op_done;	/* The last finished op of the resource */
	guint		delay_timeout;  /* The delay value of op_list execution */
	int			state;  /* status of the resource */
};

struct lrmd_op
{
	char*			rsc_id;
	gboolean		is_copy;
	pid_t			client_id;
	int			call_id;
	int			exec_pid;
	guint			repeat_timeout_tag;
	int			interval;
	int			delay;
	gboolean		is_cancelled;
	int			weight;
	int			copyparams;
	struct ha_msg*		msg;
	ra_pipe_op_t *		rapop;
	char			first_line_ra_stdout[80]; /* only for heartbeat RAs*/
	/*time stamps*/
	longclock_t		t_recv; /* set in lrmd_op_new(), i.e. on op create */
	longclock_t		t_addtolist; /* set in add_op_to_runlist() */
	longclock_t		t_perform; /* set in perform_ra_op() */
	longclock_t		t_done; /* set in on_op_done() */
	longclock_t		t_rcchange; /* set in on_op_done(), could equal t_perform */
	longclock_t		t_lastlogmsg; /* the last time the monitor op was logged */
	ProcTrackKillInfo	killseq[3];
};


/* For reading the output from executing the RA */
struct ra_pipe_op
{
	/* The same value of the one in corresponding lrmd_op */
	lrmd_op_t *	lrmd_op;
	int		ra_stdout_fd;
	int		ra_stderr_fd;
	GFDSource *	ra_stdout_gsource;
	GFDSource *	ra_stderr_gsource;
	gboolean	first_line_read;

	/* For providing more detailed information in log */
	char *		rsc_id;
	char *		op_type;
	char *		rsc_class;
};


const char *gen_op_info(const lrmd_op_t* op, gboolean add_params);
#define op_info(op) gen_op_info(op,TRUE)
#define small_op_info(op) gen_op_info(op,FALSE)

#define DOLRMAUDITS
#undef DOLRMAUDITS

#define DOMEGALRMAUDITS
#define LRMAUDIT_CLIENTS
#define LRMAUDIT_RESOURCES

#ifdef DOLRMAUDITS

	void lrmd_audit(const char *function, int line);
	void audit_clients(void);
	void audit_resources(void);
	void audit_ops(GList* rsc_ops, lrmd_rsc_t *rsc, const char *desc);
	void on_client(gpointer key, gpointer value, gpointer user_data);
	void on_resource(gpointer key, gpointer value, gpointer user_data);
	void on_op(lrmd_op_t *op, lrmd_rsc_t *rsc, const char *desc);
	void on_ra_pipe_op(ra_pipe_op_t *rapop, lrmd_op_t *op, const char *desc);

#	define LRMAUDIT() lrmd_audit(__FUNCTION__,__LINE__)
#	ifdef DOMEGALRMAUDITS
#		define MEGALRMAUDIT lrmd_audit(__FUNCTION__,__LINE__)
#	else
#		define MEGALRMAUDIT /*nothing*/
#	endif
#else
#	define LRMAUDIT() /*nothing*/
#	define MEGALRMAUDIT() /*nothing*/
#endif

/*
 * load parameters from an ini file (cib_secrets.c)
 */
int replace_secret_params(char* rsc_id, GHashTable* params);
