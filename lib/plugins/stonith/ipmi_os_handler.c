/*
 * This program is largely based on the ipmicmd.c program that's part of OpenIPMI package.
 * 
 * Copyright Intel Corp. 
 * Yixiong.Zou@intel.com
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
 */

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <OpenIPMI/os_handler.h>
#include <OpenIPMI/selector.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


#include <OpenIPMI/ipmi_int.h>

#include <time.h>

extern selector_t *os_sel;

#if 0
static void check_no_locks(os_handler_t *handler);
#define CHECK_NO_LOCKS(handler) check_no_locks(handler)
#else
#define CHECK_NO_LOCKS(handler) do {} while(0)
#endif

struct os_hnd_fd_id_s
{
    int             fd;
    void            *cb_data;
    os_data_ready_t data_ready;
    os_handler_t    *handler;
};

static void
fd_handler(int fd, void *data)
{

    os_hnd_fd_id_t *fd_data = (os_hnd_fd_id_t *) data;

    CHECK_NO_LOCKS(fd_data->handler);
    fd_data->data_ready(fd, fd_data->cb_data, fd_data);
    CHECK_NO_LOCKS(fd_data->handler);
}

static int
add_fd(os_handler_t    *handler,
       int             fd,
       os_data_ready_t data_ready,
       void            *cb_data,
       os_hnd_fd_id_t  **id)
{
    os_hnd_fd_id_t *fd_data;

    fd_data = ipmi_mem_alloc(sizeof(*fd_data));
    if (!fd_data)
	return ENOMEM;

    fd_data->fd = fd;
    fd_data->cb_data = cb_data;
    fd_data->data_ready = data_ready;
    fd_data->handler = handler;
    sel_set_fd_handlers(os_sel, fd, fd_data, fd_handler, NULL, NULL, NULL);
    sel_set_fd_read_handler(os_sel, fd, SEL_FD_HANDLER_ENABLED);
    sel_set_fd_write_handler(os_sel, fd, SEL_FD_HANDLER_DISABLED);
    sel_set_fd_except_handler(os_sel, fd, SEL_FD_HANDLER_DISABLED);

    *id = fd_data;
    return 0;
}

static int
remove_fd(os_handler_t *handler, os_hnd_fd_id_t *fd_data)
{
    sel_clear_fd_handlers(os_sel, fd_data->fd);
    sel_set_fd_read_handler(os_sel, fd_data->fd, SEL_FD_HANDLER_DISABLED);
    ipmi_mem_free(fd_data);
    return 0;
}

struct os_hnd_timer_id_s
{
    void           *cb_data;
    os_timed_out_t timed_out;
    sel_timer_t    *timer;
    int            running;
    os_handler_t   *handler;
};

static void
timer_handler(selector_t  *sel,
	      sel_timer_t *timer,
	      void        *data)
{
    os_hnd_timer_id_t *timer_data = (os_hnd_timer_id_t *) data;
    void              *cb_data;
    os_timed_out_t    timed_out;

    CHECK_NO_LOCKS(timer_data->handler);
    timed_out = timer_data->timed_out;
    cb_data = timer_data->cb_data;
    timer_data->running = 0;
    timed_out(cb_data, timer_data);
    CHECK_NO_LOCKS(timer_data->handler);
}

static int
start_timer(os_handler_t      *handler, 
	    os_hnd_timer_id_t *id,
	    struct timeval    *timeout,
	    os_timed_out_t    timed_out,
	    void              *cb_data)
{
    struct timeval    now;

    if (id->running)
	return EBUSY;

    id->running = 1;
    id->cb_data = cb_data;
    id->timed_out = timed_out;

    gettimeofday(&now, NULL);
    now.tv_sec += timeout->tv_sec;
    now.tv_usec += timeout->tv_usec;
    while (now.tv_usec >= 1000000) {
	now.tv_usec -= 1000000;
	now.tv_sec += 1;
    }

    return sel_start_timer(id->timer, &now);
}

static int
stop_timer(os_handler_t *handler, os_hnd_timer_id_t *timer_data)
{
    return sel_stop_timer(timer_data->timer);
}

static int
alloc_timer(os_handler_t      *handler, 
	    os_hnd_timer_id_t **id)
{
    os_hnd_timer_id_t *timer_data;
    int               rv;

    timer_data = ipmi_mem_alloc(sizeof(*timer_data));
    if (!timer_data)
	return ENOMEM;

    timer_data->running = 0;
    timer_data->timed_out = NULL;
    timer_data->handler = handler;

    rv = sel_alloc_timer(os_sel, timer_handler, timer_data,
			 &(timer_data->timer));
    if (rv) {
	ipmi_mem_free(timer_data);
	return rv;
    }

    *id = timer_data;
    return 0;
}

static int
free_timer(os_handler_t *handler, os_hnd_timer_id_t *timer_data)
{
    sel_free_timer(timer_data->timer);
    ipmi_mem_free(timer_data);
    return 0;
}

static int
get_random(os_handler_t *handler, void *data, unsigned int len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    int rv;

    if (fd == -1)
	return errno;

    rv = read(fd, data, len);

    close(fd);
    return rv;
}

static void
sui_log(os_handler_t         *handler,
	enum ipmi_log_type_e log_type,
	char                 *format,
	...)
{
	return;
}

static void
sui_vlog(os_handler_t         *handler,
	 enum ipmi_log_type_e log_type,
	 char                 *format,
	 va_list              ap)
{
	return;
}


os_handler_t ipmi_os_cb_handlers =
{
    .add_fd_to_wait_for = add_fd,
    .remove_fd_to_wait_for = remove_fd,

    .start_timer = start_timer,
    .stop_timer = stop_timer,
    .alloc_timer = alloc_timer,
    .free_timer = free_timer,

    .create_lock = NULL,
    .destroy_lock = NULL,
    .is_locked = NULL,
    .lock = NULL,
    .unlock = NULL,
    .create_rwlock = NULL,
    .destroy_rwlock = NULL,
    .read_lock = NULL,
    .write_lock = NULL,
    .read_unlock = NULL,
    .write_unlock = NULL,
    .is_readlocked = NULL,
    .is_writelocked = NULL,

    .get_random = get_random,

    .log = sui_log,
    .vlog = sui_vlog 
};


