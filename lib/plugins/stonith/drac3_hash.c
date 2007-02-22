/*
 * Stonith module for Dell DRACIII (Dell Remote Access Card)
 *
 * Copyright (C) 2003 Alfa21 Outsourcing
 * Copyright (C) 2003 Roberto Moreda <moreda@alfa21.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */

#include <lha_internal.h>

#include <string.h>
#include <stdio.h>
#include <clplumbing/base64.h>
#include <clplumbing/md5.h>
#include <glib.h>

#include "drac3_hash.h"

#define BUFLEN        1024    /* buffer */
#define SBUFLEN        256    /* small buffer */
#define MD5LEN          16    /* md5 buffer */

/* Hash functions for DRAC3 authentication */

guint16 
drac3Crc16(const char *str, 
	const int l) {

    int i,j;
    guint16 crc = 0;
    
    for (i=0; i<l; i++) {
        crc = crc ^ (str[i] << 8);
        for (j=0; j<8; j++)  
            crc = ( (crc & 0x8000) == 32768 ? (crc<<1) ^ 0x1021 : crc<<1);
    }    
    crc = crc & 0xFFFF;
    return crc;
}

void 
drac3AuthHash(const char * chall, 
	const char * pass, 
	char * token, 
	int len) {
    
    char * chall_dup;    
    char challBytes[MD5LEN];
    char passMD5[MD5LEN];
    char xorBytes[MD5LEN];
    char xorBytesMD5[MD5LEN];
    guint16 crc;
    char response[MD5LEN+2];
    char responseb64[SBUFLEN];
    int i;
    
    /* decodes chall -> challBytes */
    memset(challBytes, 0, MD5LEN);
    chall_dup = g_strdup(chall);
    if (chall_dup[strlen(chall_dup) - 1] == '\n' ) {
        chall_dup[strlen(chall_dup) - 1] = '\0';
    }
    base64_to_binary(chall_dup, strlen(chall_dup), challBytes, MD5LEN);

    /* gets MD5 from pass -> passMD5 */
    MD5((const unsigned char *)pass, strlen(pass), (unsigned char *)passMD5);
    
    /* calculate challBytes and passMD5 xor -> xorBytes */
    for (i=0; i<MD5LEN; i++) {
        xorBytes[i] = challBytes[i] ^ passMD5[i];
    }
    
    /* calculate xorBytes MD5 -> xorBytesMD5 */
    MD5((unsigned char *)xorBytes, MD5LEN, (unsigned char *)xorBytesMD5);

    /* calculate xorBytesMD5 crc16 */
    crc = drac3Crc16(xorBytesMD5, MD5LEN);
    
    /* joins xorBytesMD5 and crc16 -> response */
    memcpy(response, xorBytesMD5, MD5LEN);
    memcpy(response+MD5LEN, &crc, 2);
    
    /* calculate response base64 -> responseb64 */
    memset(responseb64, 0, SBUFLEN);
    binary_to_base64(response, MD5LEN+2, responseb64, SBUFLEN);

    /* assuring null-termination */
    responseb64[SBUFLEN-1]=0x00;
    
    snprintf(token, len, "%s", responseb64);
    token[len-1]=0x00;
}
