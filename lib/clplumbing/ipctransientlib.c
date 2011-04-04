/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <ipctransient.h>

/* for basename() on some OSes (e.g. Solaris) */
#include <libgen.h>

#define WORKING_DIR HA_VARLIBHBDIR

const char *procname = NULL;

const char *commdir = WORKING_DIR;

void
trans_getargs(int argc, char **argv)
{
	int argflag, argerrs;

	procname = basename(argv[0]);

        argerrs = 0;
        while ((argflag = getopt(argc, argv, "C:")) != EOF) {
                switch (argflag) {
                case 'C':       /* directory to commpath */
                        commdir = optarg;
                        break;
                default:
                        argerrs++;
                        break;
                }
        }
        if (argerrs) {
                fprintf(stderr,
                     "Usage: %s [-C commdir]\n"
                        "\t-C : directory to commpath (default %s)\n",
                  procname, WORKING_DIR);
                exit(1);
	}

}

void
default_ipctest_input_destroy(gpointer user_data)
{
    cl_log(LOG_INFO, "default_ipctest_input_destroy:received HUP");
}

IPC_Message *
create_simple_message(const char *text, IPC_Channel *ch)
{
    IPC_Message *ack_msg = NULL;
    char *copy_text = NULL;

    if(text == NULL) {
		cl_log(LOG_ERR, "ERROR: can't create IPC_Message with no text");
		return NULL;
	} else if(ch == NULL) {
		cl_log(LOG_ERR, "ERROR: can't create IPC_Message with no channel");
		return NULL;
	}

    ack_msg = (IPC_Message *)malloc(sizeof(IPC_Message));
    if (ack_msg == NULL){
	    cl_log(LOG_ERR, "create_simple_message:"
		   "allocating memory for IPC_Message failed");		
	    return NULL;
    }
    
    memset(ack_msg, 0, sizeof(IPC_Message));
    
    copy_text = strdup(text);
    
    ack_msg->msg_private = NULL;
    ack_msg->msg_done    = NULL;
    ack_msg->msg_body    = copy_text;
    ack_msg->msg_ch      = ch;

    ack_msg->msg_len = strlen(text)+1;
    
    return ack_msg;
}
