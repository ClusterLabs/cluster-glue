/*
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _CLPLUMBING_BASE64_H
#	define _CLPLUMBING_BASE64_H
/*
 *
 * Base64 conversion functions.
 * They convert from a binary array into a single string
 * in base 64.  This is almost (but not quite) like section 5.2 of RFC 1341
 * The only difference is that we don't care about line lengths.
 * We do use their encoding algorithm.
 *
 */

#define	B64inunit	3
#define	B64outunit	4

/* How long will the base64 string be for a particular binary object size? */
/* This is like strlen() and doesn't include the '\0' byte at the end */
#define	B64_stringlen(bytes)	\
	((((bytes)+(B64inunit-1))/B64inunit)*B64outunit)

/* How many bytes to you need to malloc to store a base64 string? */
/* (includes space for the '\0' terminator byte) */
#define	B64_stringspace(bytes)	(B64_stringlen(bytes)+1)

/* How many bytes will a base64 string take up back in binary? */
/* Note:  This may be as much as two 2 bytes more than strictly needed */
#define	B64_maxbytelen(slen)	(((slen) / B64outunit)*B64inunit)

/* Returns strlen() of base64 string returned in "output" */
int binary_to_base64(const void * data, int nbytes, char * output, int outlen);

/* Returns the size of the binary object we returned in "output" */
int base64_to_binary(const char * input, int inlen, void * output, int outlen);
#endif
