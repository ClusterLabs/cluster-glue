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
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <curl/curl.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "drac3_command.h"
#include "drac3_hash.h"

#define BUFLEN        1024    /* buffer */
#define SBUFLEN        256    /* small buffer */
#define MD5LEN          16    /* md5 buffer */

#define DEBUG 		 0

/* Hardcoded XML commands and response codes */
#define CMD_POWERCYCLE 	"<?XML version=\"1.0\"?><?RMCXML version=\"1.0\"?><RMCSEQ><REQ CMD=\"serveraction\"><ACT>powercycle</ACT></REQ></RMCSEQ>\n"
#define CMD_GETSYSINFO	"<?XML version=\"1.0\"?><?RMCXML version=\"1.0\"?><RMCSEQ><REQ CMD=\"xml2cli\"><CMDINPUT>getsysinfo -A</CMDINPUT></REQ></RMCSEQ>\n"
#define RC_OK "0x0\n"

struct Chunk {
	char *memory;
	size_t size;
};

/* prototypes */
int xmlGetXPathString (const char *str, const char * expr, char * rc, const int len);
size_t writeFunction (void *ptr, size_t size, size_t nmemb, void *data);
	

/* ---------------------------------------------------------------------- *
 * XML PARSING                                                            *
 * ---------------------------------------------------------------------- */
 
int 
xmlGetXPathString (const char *str, 
		   const char * expr, 
		   char * rc, 
		   const int len) 
{	
    xmlDocPtr doc;
    xmlNodePtr cur;
    xmlXPathContextPtr ctx;
    xmlXPathObjectPtr path; 
    xmlChar *xmlRC;    
    
    if (!strchr(str,'<')) {
        fprintf(stderr,"%s malformed\n", str);
        rc[0] = 0x00;
        return(1);
    }

    doc = xmlParseMemory(str, strlen(str));
    xmlXPathInit();
    ctx = xmlXPathNewContext(doc);
    path = xmlXPathEvalExpression((const xmlChar *)expr, ctx);
    cur = path->nodesetval->nodeTab[0]; 
    
    if (cur != NULL) {
	xmlRC = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
	snprintf(rc, len, "%s\n", xmlRC);
	xmlFree(xmlRC);
	xmlFreeDoc(doc);
	xmlCleanupParser();
	xmlXPathFreeObject(path);
	xmlXPathFreeContext(ctx); 
	    
        return(0);
    } else {
        fprintf(stderr,"error in obtaining XPath %s\n", expr);
        xmlFreeDoc(doc);
	xmlCleanupParser();
	xmlXPathFreeObject(path);
	xmlXPathFreeContext(ctx); 
	
	rc[0] = 0x00;
        return(1);
    }
}


/* ---------------------------------------------------------------------- *
 * CURL CALLBACKS                                                         *
 * ---------------------------------------------------------------------- */
 
size_t
writeFunction (void *ptr, size_t size, size_t nmemb, void *data)
{

    register int realsize = size * nmemb;
    struct Chunk *mem = (struct Chunk *)data;

    mem->memory = (char *)realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory) {
        memcpy(&(mem->memory[mem->size]), ptr, realsize);
        mem->size += realsize;
        mem->memory[mem->size] = 0;
    }
    return realsize;
}


/* ---------------------------------------------------------------------- *
 * DRAC3 CURL COMMANDS                                                    *
 * ---------------------------------------------------------------------- */
 
int 
drac3InitCurl (CURL *curl)
{
#ifdef CURLOPT_NOSIGNAL
    if (curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1)) return(1);
#endif
    if (curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30)) return(1);
    if (curl_easy_setopt(curl, CURLOPT_VERBOSE, 0)) return(1);
    if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFunction)) return(1);
    if (curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "/dev/null")) return(1);
    if (curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0)) return(1);
    if (curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0)) return(1);
    return(0);
}

int
drac3Login (CURL *curl, 
            const char *host,
	    const char *user,
	    const char *pass)
{
    char url[BUFLEN];
    char chall[BUFLEN];
    char token[BUFLEN];
    char rc[SBUFLEN];
    int status;
    struct Chunk chunk;
    
    chunk.memory = NULL;
    chunk.size = 0;
    if (curl_easy_setopt(curl, CURLOPT_FILE, (void *)&chunk))
	    return(1);
 
    /* ask for challenge */
    snprintf(url, BUFLEN, "https://%s/cgi/challenge", host);
    url[BUFLEN-1] = 0x00;

    if (curl_easy_setopt(curl, CURLOPT_URL, url)) 
	    return(1);
    if (curl_easy_perform(curl)) 
	    return(1);

    /* extract challenge */
    status = xmlGetXPathString(chunk.memory, "//CHALLENGE", chall, BUFLEN);
    if (status) {
	    free(chunk.memory);
	    return(1);
    }
    
    /* calculate authToken */
    drac3AuthHash(chall, pass, token, BUFLEN);

    if (DEBUG) printf("T: %s\n", token);
    
    status = xmlGetXPathString(chunk.memory, "//RC", rc, SBUFLEN);
    if (status) {
	    free(chunk.memory);
	    return(1);
    }

    if (DEBUG) printf("RC: %s\n", rc);

    status = (strcmp(rc, RC_OK) == 0) ? 0 : 1;	
    free(chunk.memory);
    if (status) return(1);
    chunk.memory = NULL;
    chunk.size = 0;
    
    /* sends authToken */
    snprintf(url, BUFLEN, "https://%s/cgi/login?user=%s&hash=%s",
		    host,
		    user,
		    token);
    url[BUFLEN-1] = 0x00;
    
    if (curl_easy_setopt(curl, CURLOPT_URL, url))
	    return(1);
    if (curl_easy_perform(curl))
	    return(1);
    
    if (DEBUG) printf("R: %s\n", chunk.memory);
    status = xmlGetXPathString(chunk.memory, "//RC", rc, SBUFLEN);
    if (status) {
	    free(chunk.memory);
	    return(1);
    }
    
    if (DEBUG) printf("RC: %s\n", rc);
    
    status = (strcmp(rc, RC_OK) == 0) ? 0 : 1;
    free(chunk.memory);
    return(status);
}

int
drac3PowerCycle (CURL *curl, 
		 const char *host)
{
    char url[BUFLEN];
    char cmd[]=CMD_POWERCYCLE;
    char rc[SBUFLEN];
    int status;
    struct Chunk chunk;
    
    chunk.memory = NULL;
    chunk.size = 0;
    if (curl_easy_setopt(curl, CURLOPT_FILE, (void *)&chunk)) return(1);
    
    snprintf(url, BUFLEN, "https://%s/cgi/bin",
		    host);
    url[BUFLEN-1] = 0x00;
    
    if (curl_easy_setopt(curl, CURLOPT_URL, url)) return(1);
    if (curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cmd)) return(1);
    if (curl_easy_perform(curl)) return(1);
    
    if (DEBUG) printf("R: %s\n", chunk.memory);
    status = xmlGetXPathString(chunk.memory, "//RC", rc, SBUFLEN);
    if (status) {
	    free(chunk.memory);
	    return(1);
    }
 if (DEBUG) printf("RC: %s\n", rc);

    status = (strcmp(rc, RC_OK) == 0) ? 0 : 1;
    free(chunk.memory);
    return(status);
}


int
drac3GetSysInfo (CURL *curl, 
		 const char *host)
{
    char url[BUFLEN];
    char cmd[]=CMD_GETSYSINFO;
    char rc[SBUFLEN];
    int status;
    struct Chunk chunk;
    
    chunk.memory = NULL;
    chunk.size = 0;
    if (curl_easy_setopt(curl, CURLOPT_FILE, (void *)&chunk)) return(1);
    
    snprintf(url, BUFLEN, "https://%s/cgi/bin",
		    host);
    url[BUFLEN-1] = 0x00;
    
    if (curl_easy_setopt(curl, CURLOPT_URL, url)) return(1);
    if (curl_easy_setopt(curl, CURLOPT_POSTFIELDS, cmd)) return(1);
    if (curl_easy_perform(curl)) return(1);
    
    if (DEBUG) printf("R: %s\n", chunk.memory);
    status = xmlGetXPathString(chunk.memory, "//RC", rc, SBUFLEN);
    if (status) {
	    free(chunk.memory);
	    return(1);
    }
     if (DEBUG) printf("RC: %s\n", rc);

    status = (strcmp(rc, RC_OK) == 0) ? 0 : 1;
    free(chunk.memory);
    return(status);
}
 

int
drac3Logout (CURL *curl,
             const char *host)
{
    char url[BUFLEN];
    char rc[SBUFLEN];
    int status;
    struct Chunk chunk;
    
    chunk.memory = NULL;
    chunk.size = 0;
    if (curl_easy_setopt(curl, CURLOPT_FILE, (void *)&chunk)) return(1);
    
    snprintf(url, BUFLEN, "https://%s/cgi/logout",
		    host);
    url[BUFLEN-1] = 0x00;
    
    if (curl_easy_setopt(curl, CURLOPT_URL, url)) return(1);
    if (curl_easy_perform(curl)) return(1);
    
    if (DEBUG) printf("R: %s\n", chunk.memory);
    status = xmlGetXPathString(chunk.memory, "//RC", rc, SBUFLEN);
    if (status) {
	    free(chunk.memory);
	    return(1);
    }
     if (DEBUG) printf("RC: %s\n", rc);

    status = (strcmp(rc, RC_OK) == 0) ? 0 : 1;
    free(chunk.memory);
    return(status);
}

int
drac3VerifyLogin (CURL *curl,
		  const char *host)
{	
	/*We try to do a GetSysInfo */
	return(drac3GetSysInfo (curl, host));
}
	
/* -------------------------------------------------------------------- */

