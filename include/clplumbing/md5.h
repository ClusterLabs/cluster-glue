/*
 * md5.h: MD5 and keyed-MD5 algorithms
 *
 * Author:  Sun Jiang Dong <sunjd@cn.ibm.com>
 * Copyright (c) 2005 International Business Machines
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

#ifndef _MD5_H_
#define _MD5_H__

/*
 *      MD5:		The MD5 Message-Digest Algorithm ( RFC 1321 )
 *      return value:   0  - success
 *			<0 - fail 
 *      Note:           The digest buffer should be not less than 16.
 *                      
 */
int MD5(  const unsigned char *data
	, unsigned long data_len
	, unsigned char * digest);

/*
 *      HMAC:		Keyed-Hashing for Message Authentication
 *      return value:   0  - success
 *			<0 - fail 
 *      Note:           The digest buffer should be not less than 16.
 */
int HMAC( const unsigned char * key
	, unsigned int key_len
	, const unsigned char * data
	, unsigned long data_len
	, unsigned char * digest);

#endif
