/*
 *
 * ocf_ipc.c: IPC abstraction implementation.
 *
 *
 * Copyright (c) 2002 Xiaoxiang Liu <xiliu@ncsa.uiuc.edu>
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
#include <clplumbing/ipc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <portability.h>

struct IPC_WAIT_CONNECTION * socket_wait_conn_new(GHashTable* ch_attrs);
struct IPC_CHANNEL * socket_client_channel_new(GHashTable* ch_attrs);

struct IPC_WAIT_CONNECTION * 
ipc_wait_conn_constructor(const char * ch_type, GHashTable* ch_attrs)
{
  if (strcmp(ch_type, "domain_socket") == 0
  ||	strcmp(ch_type, IPC_ANYTYPE) == 0
  ||	strcmp(ch_type, IPC_DOMAIN_SOCKET) == 0) {
    return socket_wait_conn_new(ch_attrs);
  }
  return NULL;
}

struct IPC_CHANNEL * 
ipc_channel_constructor(const char * ch_type, GHashTable* ch_attrs)
{
  if	(strcmp(ch_type, "domain_socket") == 0
  ||	strcmp(ch_type, IPC_DOMAIN_SOCKET) == 0) {

	return socket_client_channel_new(ch_attrs);
  }
  return NULL;
}


struct IPC_AUTH * 
ipc_set_auth(uid_t * a_uid, gid_t * a_gid, int num_uid, int num_gid)
{
  struct IPC_AUTH *temp_auth;
  int i, v;

  v = 1;
  temp_auth = g_new(struct IPC_AUTH, 1);
  temp_auth->uid = g_hash_table_new(g_int_hash, g_int_equal);
  temp_auth->gid = g_hash_table_new(g_int_hash, g_int_equal);

  if (num_uid > 0) {
    for (i=0; i<num_uid; i++) {
      g_hash_table_insert(temp_auth->uid, &a_uid[i], &v);
    }
  }

  if (num_gid > 0) {
    for (i=0; i<num_gid; i++) {
      g_hash_table_insert(temp_auth->gid, &a_gid[i], &v);
    }
  }

  return temp_auth;
}

void
ipc_destroy_auth(struct IPC_AUTH *auth)
{
  if(auth != NULL)
    free((void *)auth);
}
