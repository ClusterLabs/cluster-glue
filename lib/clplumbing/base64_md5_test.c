/* File: base64_md5_test.c
 * Description: base64 and md5 algorithm tests
 *
 * Author: Sun Jiang Dong <sunjd@cn.ibm.com>
 * Copyright (c) 2005 International Business Machines
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

#include <lha_internal.h>
#include <stdio.h>
#include <string.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/base64.h>
#include <clplumbing/md5.h>

#define MD5LEN   16 /* md5 buffer */
#define BASE64_BUF_LEN  32

/*  gcc -o base64_md5_test base64_md5_test.c  -lplumb */
int main(void)
{
	int error_count = 0;

	const char base64_encode[] = "YWJjZGVmZ2g=";
	const char raw_data[] = "abcdefgh";

	/* A test case from 
	 * RFC 1321 - The MD5 Message-Digest Algorithm
	 */
	const char * data1 = "message digest";
	const char digest_rfc1321[(MD5LEN+1)*2+1] 
			= "f96b697d7cb7938d525a2f31aaf161d0";
	
	/* A test case from 
	 * RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
	 */
  	const char *key =   "Jefe";
	const char *data2 =  "what do ya want for nothing?";
	const char digest_rfc2104[(MD5LEN+1)*2+1] 
			= "750c783e6ab0b503eaa86e310a5db738";

	char buffer_tmp[BASE64_BUF_LEN];

	char md[(MD5LEN+1)*2+1];
	unsigned char digest[MD5LEN];
	char * md_tmp;
	int rc,i;

	/* base64 encode test */
	binary_to_base64(raw_data, strlen(raw_data), buffer_tmp
			, BASE64_BUF_LEN);
	/* printf("base64_encode = %s\n", buffer_tmp); */
	if (0 != strncmp(buffer_tmp, base64_encode, strlen(buffer_tmp)) ) {
		cl_log(LOG_ERR, "binary_to_base64 works bad.");
		error_count++;
	}

	/* base64 decode test */
	memset(buffer_tmp, 0, BASE64_BUF_LEN);
	base64_to_binary(base64_encode, strlen(base64_encode)
			, buffer_tmp, BASE64_BUF_LEN);
	/* printf("decoded data= %s\n", buffer_tmp); */
	if (0 != strncmp(buffer_tmp, raw_data, strlen(buffer_tmp)) ) {
		cl_log(LOG_ERR, "base64_to_binary works bad.");
		error_count++;
	}

	rc = MD5((const unsigned char *)data1, strlen(data1), digest);

	md_tmp = md;
        for (i = 0; i < MD5LEN; i++) {
                snprintf(md_tmp, sizeof(md), "%02x", digest[i]);
                md_tmp += 2;
        }
        *md_tmp = '\0';
	/* printf("rc=%d MD5=%s\n", rc, md); */

	if (0 != strncmp(md, digest_rfc1321, MD5LEN*2) ) {
		cl_log(LOG_ERR, "The md5-rfc1321 algorithm works bad.");
		error_count++;
	}

	rc = HMAC((const unsigned char *)key, strlen(key)
		  , (const unsigned char *)data2, strlen(data2), digest);
	md_tmp = md;
        for (i = 0; i < MD5LEN; i++) {
                sprintf(md_tmp,"%02x", digest[i]);
                md_tmp += 2;
        }
        *md_tmp = '\0';
	/* printf("rc=%d HMAC=%s\n", rc, md); */

	if (0 != strncmp(md, digest_rfc2104, MD5LEN*2) ) {
		cl_log(LOG_ERR, "The md5-rfc2104 algorithm works bad.");
		error_count++;
	}

        (void) rc; /* Suppress -Werror=unused-but-set-variable  */
	return error_count;
}
