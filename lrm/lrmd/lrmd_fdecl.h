/* TODO: This ought to be broken up into several source files for easier
 * reading and debugging. */

/* Debug oriented funtions */
static gboolean debug_level_adjust(int nsig, gpointer user_data);
static void dump_data_for_debug(void);

/* glib loop call back functions */
static gboolean on_connect_cmd(IPC_Channel* ch_cmd, gpointer user_data);
static gboolean on_connect_cbk(IPC_Channel* ch_cbk, gpointer user_data);
static int msg_type_cmp(const void *p1, const void *p2);
static gboolean on_receive_cmd(IPC_Channel* ch_cmd, gpointer user_data);
static gboolean on_repeat_op_readytorun(gpointer data);
static void on_remove_client(gpointer user_data);
static void destroy_pipe_ra_stderr(gpointer user_data);
static void destroy_pipe_ra_stdout(gpointer user_data);

/* message handlers */
static int on_msg_register(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_rsc_classes(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_rsc_types(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_rsc_providers(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_metadata(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_add_rsc(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_rsc(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_last_op(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_all(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_del_rsc(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_cancel_op(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_flush_all(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_perform_op(lrmd_client_t* client, struct ha_msg* msg);
static int on_msg_get_state(lrmd_client_t* client, struct ha_msg* msg);
static gboolean sigterm_action(int nsig, gpointer unused);

/* functions wrap the call to ra plugins */
static int perform_ra_op(lrmd_op_t* op);

/* Apphb related functions */
static int init_using_apphb(void);
static gboolean emit_apphb(gpointer data);

/* Utility functions */
static int flush_op(lrmd_op_t* op);
static gboolean rsc_execution_freeze_timeout(gpointer data);
static void add_op_to_runlist(lrmd_rsc_t* rsc, lrmd_op_t* op);
static int perform_op(lrmd_rsc_t* rsc);
static int unregister_client(lrmd_client_t* client);
static int on_op_done(lrmd_rsc_t* rsc, lrmd_op_t* op);
static int send_ret_msg ( IPC_Channel* ch, int rc);
static void notify_client(lrmd_op_t* op);
static lrmd_client_t* lookup_client (pid_t pid);
static lrmd_rsc_t* lookup_rsc (const char* rid);
static lrmd_rsc_t* lookup_rsc_by_msg (struct ha_msg* msg);
static int read_pipe(int fd, char ** data, gpointer user_data);
static gboolean handle_pipe_ra_stdout(int fd, gpointer user_data);
static gboolean handle_pipe_ra_stderr(int fd, gpointer user_data);
static struct ha_msg* op_to_msg(lrmd_op_t* op);
static gboolean lrm_shutdown(void);
static gboolean can_shutdown(void);
static gboolean free_str_hash_pair(gpointer key
,	 gpointer value, gpointer user_data);
static gboolean free_str_op_pair(gpointer key
,	 gpointer value, gpointer user_data);
static lrmd_op_t* lrmd_op_copy(const lrmd_op_t* op);
static void send_last_op(gpointer key, gpointer value, gpointer user_data);
static void record_op_completion(lrmd_client_t* client, lrmd_rsc_t* rsc, lrmd_op_t* op);
static void remove_op_history(lrmd_op_t* op);
static void hash_to_str(GHashTable * , GString *);
static void hash_to_str_foreach(gpointer key, gpointer value, gpointer userdata);
static void warning_on_active_rsc(gpointer key, gpointer value, gpointer user_data);
static void check_queue_duration(lrmd_op_t* op);
static gboolean flush_all(GList** listp);
static gboolean cancel_op(GList** listp,int cancel_op_id);

/*
 * following functions are used to monitor the exit of ra proc
 */
static void on_ra_proc_registered(ProcTrack* p);
static void on_ra_proc_finished(ProcTrack* p, int status
,			int signo, int exitcode, int waslogged);
static const char* on_ra_proc_query_name(ProcTrack* p);



/*
 * Daemon functions
 *
 * copy from the code of Andrew Beekhof <andrew@beekhof.net>
 */
static void usage(const char* cmd, int exit_status);
static int init_start(void);
static int init_stop(const char *pid_file);
static int init_status(const char *pid_file, const char *client_name);
static void lrmd_rsc_dump(char* rsc_id, const char * text);
