/* $Id: lsb_exitcodes.h,v 1.3 2005/05/17 16:25:21 gshi Exp $ */
/* LSB status exit codes.
 *
 * All of these and the supporting text are taken from the LSB.
 *
 * If the status command is given, the init script will return
 * the following exit status codes.
 * 
 * 0 program is running or service is OK
 * 1 program is dead and /var/run pid file exists
 * 2 program is dead and /var/lock lock file exists
 * 3 program is stopped
 * 4 program or service status is unknown
 * 5-99 reserved for future LSB use
 * 100-149 reserved for distribution use
 * 150-199 reserved for application use
 * 200-254 reserved
 */

#define	LSB_STATUS_OK		0
#define	LSB_STATUS_VAR_PID	1
#define	LSB_STATUS_VAR_LOCK	2
#define	LSB_STATUS_STOPPED	3
#define	LSB_STATUS_UNKNOWN	4
#define	LSB_STATUS_LSBRESERVED	5
#define	LSB_STATUS_DISTRESERVED	100
#define	LSB_STATUS_APPRESERVED	150
#define	LSB_STATUS_RESERVED	200
/*
 *
 * In the case of init script commands other than "status"
 * (i.e., "start", "stop", "restart", "reload", and "force-reload"),
 * the init script must return an exit status of zero if the action
 * described by the argument has been successful. Otherwise, the
 * exit status shall be non-zero, as defined below. In addition
 * to straightforward success, the following situations are also
 * to be considered successful:
 *
 * restarting a service (instead of reloading it) with the
 *   "force-reload" argument
 * running "start" on a service already running
 * running "stop" on a service already stopped or not running
 * running "restart" on a service already stopped or not running
 * In case of an error, while processing any init script action
 * except for "status", the init script must print an error
 * message and return one of the following non-zero exit
 * status codes.
 * 
 * 1 generic or unspecified error (current practice)
 * 2 invalid or excess argument(s)
 * 3 unimplemented feature (for example, "reload")
 * 4 user had insufficient privilege
 * 5 program is not installed
 * 6 program is not configured
 * 7 program is not running
 * 8-99 reserved for future LSB use
 * 100-149 reserved for distribution use
 * 150-199 reserved for application use
 * 200-254 reserved
 *
 * All error messages must be printed on standard error.
 * All status messages must be printed on standard output.
 * (This does not prevent scripts from calling the logging
 * functions such as log_failure_msg).
 */
#define	LSB_EXIT_OK		0
#define	LSB_EXIT_GENERIC	1
#define	LSB_EXIT_EINVAL		2
#define	LSB_EXIT_ENOTSUPPORTED	3
#define	LSB_EXIT_EPERM		4
#define	LSB_EXIT_NOTINSTALLED	5
#define	LSB_EXIT_NOTCONFIGED	6
#define	LSB_EXIT_NOTRUNNING	7
#define	LSB_EXIT_LSBRESERVED	8
#define	LSB_EXIT_DISTRESERVED	100
#define	LSB_EXIT_APPRESERVED	150
#define	LSB_EXIT_RESERVED	200
