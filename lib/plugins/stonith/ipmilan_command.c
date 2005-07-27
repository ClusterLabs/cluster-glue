/* $Id: ipmilan_command.c,v 1.9 2005/07/27 01:50:51 panjiam Exp $ */
/*
 * This program is largely based on the ipmicmd.c program that's part of OpenIPMI package.
 * 
 * Copyright Intel Corp. 
 * Yixiong.Zou@intel.com
 *
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
#include <stdio.h>

#include <stdlib.h> /* malloc() */
#include <unistd.h> /* getopt() */
#include <string.h> /* strerror() */
#include <netdb.h> /* gethostbyname() */
#include <sys/types.h>
#include <sys/socket.h>

#include <OpenIPMI/selector.h>
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_posix.h>

#include "ipmilan.h"
#include <stonith/stonith.h>
#include <clplumbing/cl_log.h>

#include <pils/plugin.h>
extern const PILPluginImports*  PluginImports;

/* #define DUMP_MSG 0 */
#define OPERATION_TIME_OUT 10

os_handler_t *os_hnd;
selector_t *os_sel;
extern os_handler_t ipmi_os_cb_handlers;

typedef enum ipmi_status {
	/*
	IPMI_CONNECTION_FAILURE,
	IPMI_SEND_FAILURE,
	IPMI_BAD_REQUEST,
	IPMI_REQUEST_FAILED,
	IPMI_TIME_OUT,
	*/
	IPMI_RUNNING = 99,
} ipmi_status_t;

static ipmi_status_t gstatus;

typedef enum chassis_control_request {
	POWER_DOWN = 0X00,
	POWER_UP = 0X01,
	POWER_CYCLE = 0X02,
	HARD_RESET = 0X03,
	PULSE_DIAGNOSTIC_INTERRUPT = 0X04,
	SOFT_SHUTDOWN = 0X05
} chassis_control_request_t;

void dump_msg_data(ipmi_msg_t *msg, ipmi_addr_t *addr, char *type);
int rsp_handler(ipmi_con_t *ipmi, ipmi_msgi_t *rsp);

void send_ipmi_cmd(ipmi_con_t *con, int request);

void timed_out(selector_t *sel, sel_timer_t *timer, void *data);

void 
timed_out(selector_t  *sel, sel_timer_t *timer, void *data)
{
	PILCallLog(PluginImports->log,PIL_CRIT, "IPMI operation timed out... :(\n");
	gstatus = S_TIMEOUT;
}

void
dump_msg_data(ipmi_msg_t *msg, ipmi_addr_t *addr, char *type)
{
	ipmi_system_interface_addr_t *smi_addr = NULL;
	int i;
	ipmi_ipmb_addr_t *ipmb_addr = NULL;

	if (addr->addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
		smi_addr = (struct ipmi_system_interface_addr *) addr;

	} else if ((addr->addr_type == IPMI_IPMB_ADDR_TYPE) 
			|| (addr->addr_type == IPMI_IPMB_BROADCAST_ADDR_TYPE)) {
		ipmb_addr = (struct ipmi_ipmb_addr *) addr;
	}

	if (smi_addr) {
		fprintf(stderr, "%2.2x %2.2x %2.2x %2.2x ", 
			addr->channel,
			msg->netfn,
			smi_addr->lun,
			msg->cmd);
	} else {
		fprintf(stderr, "%2.2x %2.2x %2.2x %2.2x ", 
			addr->channel,
			msg->netfn,
			ipmb_addr->lun,
			msg->cmd);
	}

	for (i = 0; i < msg->data_len; i++) {
		if (((i%16) == 0) && (i != 0)) {
			printf("\n            ");
		}
		fprintf(stderr, "%2.2x ", msg->data[i]);
	}
	fprintf(stderr, "\n");
}

/*
 * This function gets called after the response comes back
 * from the IPMI device. 
 * 
 * Some IPMI device does not return success, 0x00, to the 
 * remote node when the power-reset was issued.
 * 
 * The host who sent the ipmi cmd might get a 0xc3,
 * a timeout instead.  This creates problems for 
 * STONITH operation, where status is critical. :( 
 * 
 * Right now I am only checking 0xc3 as the return.
 * If your IPMI device returns some wired code after 
 * reset, you might want to add it in this code block.
 *
 */

int
rsp_handler(ipmi_con_t *ipmi, ipmi_msgi_t *rsp)
{
	int rv;
	int * request;

	request = (int *) rsp->data1;

#if 0
	dump_msg_data(rsp, addr, NULL);
#endif
	rv = rsp->data[0];  
	/* some IPMI device might not issue 0x00, success, for reset command.
	   instead, a 0xc3, timeout, is returned. */
	if (rv == 0x00 || 
		(rv == 0xc3 && *request <= ST_POWEROFF && *request >= ST_GENERIC_RESET ) ) {
		gstatus = S_OK;
	} else {
		gstatus = S_RESETFAIL;
	}

	free(request);
	return gstatus;
}

void
send_ipmi_cmd(ipmi_con_t *con, int request)
{
	ipmi_addr_t addr;
	unsigned int addr_len;
	ipmi_msg_t msg;
	struct ipmi_system_interface_addr *si;
	int rv;
	ipmi_msgi_t msgi;
	/* chassis control command request is only 1 byte long */
	unsigned char cc_data = POWER_CYCLE; 

	si = (void *) &addr;
	si->lun = 0x00;
	si->channel = IPMI_BMC_CHANNEL;
	si->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	addr_len = sizeof(*si);

	msg.netfn = IPMI_CHASSIS_NETFN;
	msg.cmd = IPMI_CHASSIS_CONTROL_CMD;
	msg.data = &cc_data;
	msg.data_len = 1;

	switch (request) {
		case ST_POWERON:
			cc_data = POWER_DOWN;
			break;

		case ST_POWEROFF:
			cc_data = POWER_UP;
			break;

		case ST_GENERIC_RESET:
			cc_data = POWER_CYCLE;
			break;

		case ST_IPMI_STATUS:
			msg.netfn = IPMI_APP_NETFN;
			msg.cmd = IPMI_GET_DEVICE_ID_CMD;
			msg.data = NULL;
			msg.data_len = 0;
			break;

		default:
			gstatus = S_INVAL;
			return;
	}

	msgi.data1 = (int *) malloc(sizeof(int));
	*((int *)msgi.data1) = request;
	rv = con->send_command(con, &addr, addr_len, &msg, rsp_handler, &msgi);
	if (rv == -1) {
		PILCallLog(PluginImports->log,PIL_CRIT, "Error sending IPMI command: %x\n", rv);
		gstatus = S_ACCESS;
	}

	return;
}

static void
con_changed_handler(ipmi_con_t *ipmi,
			int err,
			unsigned int port_num,
			int still_connected,
			void *cb_data)
{
	int * request;
	if (err) {
		PILCallLog(PluginImports->log,PIL_CRIT, "Unable to setup connection: %x\n", err);
		return;
	}

	request = (int *) cb_data;
	send_ipmi_cmd(ipmi, *request);
}


static int
setup_ipmi_conn(struct ipmilanHostInfo * host, int request)
{
	int rv;

	struct hostent *ent;
	struct in_addr lan_addr[2];
	int lan_port[2];
	int num_addr = 1;
	int authtype = 0;
	int privilege = 0;
	char username[17];
	char password[17];

	static ipmi_con_t *con;

	sel_timer_t * timer;
	struct timeval timeout;

	os_hnd = ipmi_posix_get_os_handler();
	if (!os_hnd) {
	    	PILCallLog(PluginImports->log,PIL_CRIT, "ipmi_smi_setup_con: Unable to allocate os handler");
		return 1;
	}

	rv = sel_alloc_selector(os_hnd, &os_sel);
	if (rv) {
		PILCallLog(PluginImports->log,PIL_CRIT, "Could not alloctate selector\n");
		return rv;
	}

    	ipmi_posix_os_handler_set_sel(os_hnd, os_sel);

	rv = ipmi_init(os_hnd);
	if (rv) {
		PILCallLog(PluginImports->log,PIL_CRIT, "ipmi_init erro: %d ", rv);
		return rv;
	}

	ent = gethostbyname(host->ipaddr);
	if (!ent) {
		PILCallLog(PluginImports->log,PIL_CRIT, "gethostbyname failed: %s\n", strerror(h_errno));
		return 1;
	}

	memcpy(&lan_addr[0], ent->h_addr_list[0], ent->h_length);
	lan_port[0] = host->portnumber;
	lan_port[1] = 0;

	authtype = host->authtype;
	privilege = host->privilege;

	memcpy(username, host->username, sizeof(username));
	memcpy(password, host->password, sizeof(password));

	rv = ipmi_lan_setup_con(lan_addr, lan_port, num_addr, 
				authtype, privilege,
				username, strlen(username),
				password, strlen(password),
				os_hnd, os_sel,
				&con);

	if (rv) {
		PILCallLog(PluginImports->log,PIL_CRIT, "ipmi_lan_setup_con: %s\n", strerror(rv));
		return S_ACCESS;
	}

	con->set_con_change_handler(con, con_changed_handler, &request);

	gstatus = IPMI_RUNNING;

	rv = con->start_con(con);
	if (rv) {
		PILCallLog(PluginImports->log,PIL_CRIT, "Could not start IPMI connection: %x\n", rv);
		gstatus = S_BADCONFIG;
		return rv;
	}

	gettimeofday(&timeout, NULL);
	timeout.tv_sec += OPERATION_TIME_OUT;
	timeout.tv_usec += 0;

	sel_alloc_timer(os_sel, timed_out, NULL, &timer);
	sel_start_timer(timer, &timeout);

        while (1) {
                rv = sel_select(os_sel, NULL, 0, NULL, NULL);
		if (gstatus != IPMI_RUNNING) {
			break;
		}
        }

	sel_free_timer(timer);

	con->close_connection(con);
	ipmi_shutdown();
	return gstatus;
}

int
do_ipmi_cmd(struct ipmilanHostInfo * host, int request)
{
	return setup_ipmi_conn(host, request);
}

void
posix_vlog(char *format, enum ipmi_log_type_e log_type, va_list ap)
{
    int do_nl = 1; 

    switch(log_type)
    {
        case IPMI_LOG_INFO:
            PILCallLog(PluginImports->log,PIL_INFO, "INFO: ");
            break;
                                                                                                                                                             
        case IPMI_LOG_WARNING:
            PILCallLog(PluginImports->log,PIL_INFO, "WARN: ");
            break;
                                                                                                                                                             
        case IPMI_LOG_SEVERE:
            PILCallLog(PluginImports->log,PIL_INFO, "SEVR: ");
            break;
                                                                                                                                                             
        case IPMI_LOG_FATAL:
            PILCallLog(PluginImports->log,PIL_INFO, "FATL: ");
            break;
                                                                                                                                                             
        case IPMI_LOG_ERR_INFO:
            PILCallLog(PluginImports->log,PIL_INFO, "EINF: ");
            break;
                                                                                                                                                             
        case IPMI_LOG_DEBUG_START:
            do_nl = 0;
            /* FALLTHROUGH */
        case IPMI_LOG_DEBUG:
            PILCallLog(PluginImports->log,PIL_INFO, "DEBG: ");
            break;
                                                                                                                                                             
        case IPMI_LOG_DEBUG_CONT:
            do_nl = 0;
            /* FALLTHROUGH */
        case IPMI_LOG_DEBUG_END:
            break;
    }
                                                                                                                                                             
}

