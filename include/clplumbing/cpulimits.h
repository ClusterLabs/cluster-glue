/*
 * Functions to put limits on CPU consumption.
 * This allows us to better catch runaway realtime processes that
 * might otherwise hang the whole system.
 *
 * The process is basically this:
 *  - Set the CPU percentage limit with cl_cpu_limit_setpercent()
 *	according to what you expect the CPU percentage to top out at
 *	measured over an interval at >= 10 seconds
 *  - Call cl_cpu_limit_ms_interval() to figure out how often to update
 *	the CPU limit (it returns milliseconds)
 *  - At least as often as indicated above, call cl_cpu_limit_update()
 *	to update our current CPU limit.
 *
 * These limits are approximate, so be a little conservative.
 * If you've gone into an infinite loop, it'll likely get caught ;-)
 *
 * Note that exceeding the soft CPU limits we set here will cause a
 * SIGXCPU signal to be sent.
 *
 * The default action for this signal is to cause a core dump.
 * This is a good choice ;-)
 *
 * As of this writing, this code will never set the soft CPU limit less
 * than two seconds, or greater than 10 seconds.
 *
 * It will currrently return a limit update interval between 10000 and
 * 400000 milliseconds.
 *
 */

/*
 * Set expected CPU percentage upper bound
 */
int	cl_cpu_limit_setpercent(int ipercent);

/*
 * Update the current CPU limit
 */
int	cl_cpu_limit_update(void);

/*
 * How often should we call cl_cpu_limit_update()?
 *
 * Note:  return result is in milliseconds
 */
int	cl_cpu_limit_ms_interval(void);
