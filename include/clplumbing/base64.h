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

/* How many bytes will a binary object taken when converted to base64? */
#define	B64_stringlen(bytes)	\
	((((bytes)+(B64inunit-1))/B64inunit)*B64outunit)

/* How many bytes will a base64 string take up back in binary? */
/* Note:  This may be as much as two 2 bytes more than strictly needed */
#define	B64_maxbytelen(slen)	(((slen) / B64outunit)*B64inunit)

/* Returns strlen() of base64 string returned in "output" */
int binary_to_base64(void * data, int nbytes, char * output, int outlen);

/* Returns the size of the binary object we returned in "output" */
int base64_to_binary(char * input, int inlen, void * output, int outlen);
#endif
