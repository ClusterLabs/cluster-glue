#include <portability.h>
#include <heartbeat.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
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

#define	B64_stringlen(bytes)	\
	((((bytes)+(B64inunit-1))/B64inunit)*B64outunit)

#define	B64_maxbytelen(slen)	(((slen) / B64outunit)*B64inunit)


static char b64chars[]
=	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define	EQUALS	'='
#define	MASK6	(077)
#define	MASK24	(077777777)

int binary_to_base64(void * data, int nbytes, char * output, int outlen);
int base64_to_binary(char * input, int inlen, void * output, int outlen);

int
binary_to_base64(void * data, int nbytes, char * output, int outlen)
{
	int	requiredlen = B64_stringlen(nbytes)+1; /* EOS */
	char *		outptr;
	unsigned char *	inmax;
	unsigned char *	inlast;
	unsigned char *	inptr;
	int	bytesleft;

	(void)_ha_msg_h_Id;
	(void)_heartbeat_h_Id;

	assert(strlen(b64chars) == 64);
	if (outlen < requiredlen) {
		ha_log(LOG_ERR, "binary_to_base64: output area too small.");
		return -1;
	}

	inptr = data;
	/* Location of last whole 3-byte chunk */
	inmax = inptr + ((nbytes / B64inunit)*B64inunit);
	inlast = inptr + nbytes;
	outptr = output;
	

	/* Convert whole 3-byte chunks */
	for (;inptr < inmax; inptr += B64inunit) {
		unsigned long	chunk;
		unsigned int	sixbits;

		chunk =	((*inptr) << 16
		|	((*(inptr+1)) << 8)
		|	(*(inptr+2))) & MASK24;

		sixbits = (chunk >> 18) & MASK6;
		*outptr = b64chars[sixbits]; ++outptr;

//fprintf(stderr, "Adding char [%c] [%d]\n", b64chars[sixbits], sixbits);

		sixbits = (chunk >> 12) & MASK6;
		*outptr = b64chars[sixbits]; ++outptr;

//fprintf(stderr, "Adding char [%c] [%d]\n", b64chars[sixbits], sixbits);

		sixbits = (chunk >> 6) & MASK6;
		*outptr = b64chars[sixbits]; ++outptr;

//fprintf(stderr, "Adding char [%c] [%d]\n", b64chars[sixbits], sixbits);

		sixbits = (chunk & MASK6);
		*outptr = b64chars[sixbits]; ++outptr;
//fprintf(stderr, "Adding char [%c] [%d]\n", b64chars[sixbits], sixbits);
	}

	/* Do we have anything left over? */

	bytesleft = inlast - inptr;
	if (bytesleft > 0) {
		/* bytesleft can only be 1 or 2 */

		unsigned long	chunk;
		unsigned int	sixbits;

		assert(bytesleft == 1 || bytesleft == 2);

		/* Grab first byte */
		chunk =	(*inptr) << 16;

		if (bytesleft == 2) {
			/* Grab second byte */
			chunk |= ((*(inptr+1)) << 8);
		}
		chunk &= MASK24;

		/* OK, now we have our chunk... */
		sixbits = (chunk >> 18) & MASK6;
		*outptr = b64chars[sixbits]; ++outptr;
		sixbits = (chunk >> 12) & MASK6;
		*outptr = b64chars[sixbits]; ++outptr;

		if (bytesleft == 2) {
			sixbits = (chunk >> 6) & MASK6;
			*outptr = b64chars[sixbits];
		}else{
			*outptr = EQUALS;
		}
		++outptr;

		*outptr = EQUALS; ++outptr;
	}
	*outptr = EOS;	/* Don't increment */
	return (outptr - output);
}


/* This macro usable only in base64_to_binary() */

#define	Char2SixBits(in, out)  {				\
	char * ptmp;						\
	ptmp = memchr(b64chars, (in), sizeof(b64chars)-1);	\
	if (ptmp == NULL) {					\
		ha_log(LOG_ERR					\
		,	"base64_to_binary: invalid input. %d [%c]!"	\
					,	in, in);	\
		fprintf(stderr, "Line #: %d :", __LINE__);	\
		ha_log(LOG_ERR					\
		,	"string input. [%s] %d", input, inlen);\
		return -1;					\
	}							\
	out = ((ptmp-b64chars) & MASK6);			\
	}							\
	

int
base64_to_binary(char * in, int inlen, void * output, int outlen)
{
	int maxbinlen = B64_maxbytelen(inlen); /* Worst case size */
	char *		input = in;
	char *		lastinput = in + inlen - B64outunit;
	int		equalcount = 0;
	unsigned char *	startout;
	unsigned char *	out;
	unsigned	sixbits1;
	unsigned	sixbits2;
	unsigned	sixbits3;
	unsigned	sixbits4;
	unsigned long	chunk;

//fprintf(stderr, "Processing [%s]\n", input);
	/* Make sure we have enough room */
	if (outlen < maxbinlen) {
		int	residue = maxbinlen - outlen;

		if (residue > 2
		||	input[inlen-1] != EQUALS
		||	(residue == 2 && input[inlen-2] != EQUALS))  {
			ha_log(LOG_ERR
			,	"base64_to_binary: output area too small.");
			return -1;
		}
	}
	if ((inlen % 4) != 0) {
		ha_log(LOG_ERR
		,	"base64_to_binary: input length invalid.");
		return -1;
	}

	if (inlen == 0) {
		return 0;
	}

	/* We have enough space.  We are happy :-)  */

	startout = out = (char *)output;


	while (input < lastinput) {
		unsigned long	chunk;


		Char2SixBits(*input, sixbits1); ++input;
		Char2SixBits(*input, sixbits2); ++input;
		Char2SixBits(*input, sixbits3); ++input;
		Char2SixBits(*input, sixbits4); ++input;

		chunk = (sixbits1 << 18)
		|	(sixbits2 << 12) | (sixbits3 << 6) | sixbits4;


		*out = ((chunk >> 16) & 0xff);	++out;
		*out = ((chunk >>  8) & 0xff);	++out;
		*out = (chunk & 0xff);		++out;
	}

	/* Process last 4 chars of input (1 to 3 bytes of output) */

//fprintf(stderr, "Whole string: [%s], remaining [%s] lastinput[%s]\n", in, input, lastinput);


	/* The first two input chars must be normal chars */
	Char2SixBits(*input, sixbits1); ++input;
//fprintf(stderr, "Got six bits as: %d\n", sixbits1);
	Char2SixBits(*input, sixbits2); ++input;
//fprintf(stderr, "Got six bits as: %d\n", sixbits2);

	/* We should find one of: (char,char) (char,=) or (=,=) */
	/* We then output:         (3 bytes)  (2 bytes)  (1 byte) */

	if (*input == EQUALS) {
		/* The (=,=): 1 byte case */
		equalcount=2;
		sixbits3 = 0;
		sixbits4 = 0;
		/* We assume the 2nd char is an = sign :-) */
	}else{
		/* We have either the (char,char) or (char,=) case */
		Char2SixBits(*input, sixbits3); ++input;
//fprintf(stderr, "Got six bits as: %d\n", sixbits3);
		if (*input == EQUALS) {
			/* The (char, =): 2 bytes case */
			equalcount=1;
			sixbits4 = 0;
		}else{
			/* The (char, char): 3 bytes case */
			Char2SixBits(*input, sixbits4); ++input;
//fprintf(stderr, "Got six bits as: %d\n", sixbits4);
			equalcount=0;
		}
	}

	chunk = (sixbits1 << 18)
	|	(sixbits2 << 12) | (sixbits3 << 6) | sixbits4;
// fprintf(stderr, "Got chunk of: 0x%06lx %ld\n", chunk, chunk);
// fprintf(stderr, "Sixbits1 : 0x%06o\n", sixbits1);
// fprintf(stderr, "Sixbits2 : 0x%06o\n", sixbits2);
// fprintf(stderr, "Sixbits3 : 0x%06o\n", sixbits3);
// fprintf(stderr, "Sixbits4 : 0x%06o\n", sixbits4);

	/* We always have one more char to output... */
	*out = ((chunk >> 16) & 0xff); ++out;

	if (equalcount < 2) {
		/* Zero or one equal signs: total of 2 or 3 bytes output */
		*out = ((chunk >> 8) & 0xff); ++out;

		if (equalcount < 1) {
			/* No equal signs:  total of 3 bytes output */
			*out = (chunk & 0xff); ++out;
		}
	}

	return out - startout;
}

#if 0
#define RAND(upb)	(rand()%(upb))

void dumpbin(void * Bin, int length);
void randbin(void * Bin, int length);

void
dumpbin(void * Bin, int length)
{
	unsigned char *	bin = Bin;

	int	j;

	for (j=0; j < length; ++j) {
		fprintf(stderr, "%02x ", bin[j]);
		if ((j % 32) == 31) {
			fprintf(stderr, "\n");
		}
	}
	fprintf(stderr, "\n");
}

void
randbin(void * Bin, int length)
{
	unsigned char *	bin = Bin;
	int	j;

	for (j=0; j < length; ++j) {
		bin[j] = (unsigned char)RAND(256);
	}
	
}

#define MAXLEN	320
#define	MAXSTRING B64_stringlen(MAXLEN)+1
#define	MAXITER	3000000
int
main(int argc, char ** argv)
{
	int	errcount = 0;
	char	origbin[MAXLEN+1];
	char	sourcebin[MAXLEN+1];
	char	destbin[MAXLEN+1];
	char	deststr[MAXSTRING];
	int	maxiter = MAXITER;
	int	j;
	
	for (j=0; j < maxiter; ++j) {
		int	iterlen = RAND(MAXLEN+1);
		int	slen;
		int	blen;

fprintf(stderr, "+");

		memset(origbin, 0, MAXLEN+1);
		memset(sourcebin, 0, MAXLEN+1);
		memset(destbin, 0, MAXLEN+1);
		randbin(origbin, iterlen);
		origbin[iterlen] = 0x1;
		memcpy(sourcebin, origbin, iterlen);
		sourcebin[iterlen] = 0x2;
		slen = binary_to_base64(sourcebin, iterlen, deststr, MAXSTRING);
		if (slen < 0) {
			fprintf(stderr
			,	"binary_to_base64 failure: length %d\n"
			,	iterlen);
			++errcount;
			continue;
		}
		if (strlen(deststr) != slen) {
			fprintf(stderr
			,	"binary_to_base64 failure: length was %d (strlen) vs %d (ret value)\n"
			,	strlen(deststr), slen);
			fprintf(stderr, "binlen: %d, deststr: [%s]\n"
			,	iterlen, deststr);
			continue;
			++errcount;
		}
		destbin[iterlen] = 0x3;
		blen = base64_to_binary(deststr, slen, destbin, iterlen);

		if (blen != iterlen) {
			fprintf(stderr
			,	"base64_to_binary failure: length was %d vs %d\n"
			,	blen, iterlen);
			dumpbin(origbin, iterlen);
			fprintf(stderr
			,	"Base64 intermediate: [%s]\n", deststr);
			++errcount;
			continue;
		}
		if (memcmp(destbin, origbin, iterlen) != 0) {
			fprintf(stderr
			,	"base64_to_binary mismatch. Orig:\n");
			dumpbin(origbin, iterlen);
			fprintf(stderr, "Dest:\n");
			dumpbin(destbin, iterlen);
			fprintf(stderr
			,	"Base64 intermediate: [%s]\n", deststr);
			++errcount;
		}
		if (destbin[iterlen] != 0x3) {
			fprintf(stderr
			,	"base64_to_binary corruption. dest byte: 0x%02x\n"
			,	destbin[iterlen]);
			++errcount;
		}

		if (sourcebin[iterlen] != 0x2) {
			fprintf(stderr
			,	"base64_to_binary corruption. source byte: 0x%02x\n"
			,	sourcebin[iterlen]);
			++errcount;
		}
		sourcebin[iterlen] = 0x0;
		origbin[iterlen] = 0x0;
		if (memcmp(sourcebin, origbin, MAXLEN+1) != 0) {
			fprintf(stderr
			,	"base64_to_binary corruption. origbin:\n");
			dumpbin(origbin, MAXLEN+1);
			fprintf(stderr, "sourcebin:\n");
			dumpbin(sourcebin, MAXLEN+1);
			++errcount;
		}

	}

	fprintf(stderr, "%d errors.\n", errcount);

	return errcount;
}
/* HA-logging function */
void
ha_log(int priority, const char * fmt, ...)
{
	va_list		ap;
	char		buf[MAXLINE];

	va_start(ap, fmt);
	vsnprintf(buf, MAXLINE, fmt, ap);
	va_end(ap);

	fprintf(stderr, "%s\n",  buf);

}
#endif
