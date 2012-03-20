 /* zlib.c:  compression module using zlib for heartbeat.
 *
 * Copyright (C) 2005 Guochun Shi <gshi@ncsa.uiuc.edu>
 *
 * SECURITY NOTE:  It would be very easy for someone to masquerade as the
 * device that you're pinging.  If they don't know the password, all they can
 * do is echo back the packets that you're sending out, or send out old ones.
 * This does mean that if you're using such an approach, that someone could
 * make you think you have quorum when you don't during a cluster partition.
 * The danger in that seems small, but you never know ;-)
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



#define PIL_PLUGINTYPE          HB_COMPRESS_TYPE
#define PIL_PLUGINTYPE_S        HB_COMPRESS_TYPE_S
#define PIL_PLUGIN              zlib
#define PIL_PLUGIN_S            "zlib"
#define PIL_PLUGINLICENSE	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL	URL_LGPL
#include <lha_internal.h>
#include <pils/plugin.h>
#include <compress.h>
#include <zlib.h>
#include <clplumbing/cl_log.h>
#include <string.h>


static struct hb_compress_fns zlibOps;

PIL_PLUGIN_BOILERPLATE2("1.0", Debug)

static const PILPluginImports*  PluginImports;
static PILPlugin*               OurPlugin;
static PILInterface*		OurInterface;
static struct hb_media_imports*	OurImports;
static void*			interfprivate;

#define LOG	PluginImports->log
#define MALLOC	PluginImports->alloc
#define STRDUP  PluginImports->mstrdup
#define FREE	PluginImports->mfree

PIL_rc
PIL_PLUGIN_INIT(PILPlugin*us, const PILPluginImports* imports);

PIL_rc
PIL_PLUGIN_INIT(PILPlugin*us, const PILPluginImports* imports)
{
	/* Force the compiler to do a little type checking */
	(void)(PILPluginInitFun)PIL_PLUGIN_INIT;

	PluginImports = imports;
	OurPlugin = us;

	/* Register ourself as a plugin */
	imports->register_plugin(us, &OurPIExports);  

	/*  Register our interface implementation */
 	return imports->register_interface(us, PIL_PLUGINTYPE_S
	,	PIL_PLUGIN_S
	,	&zlibOps
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	interfprivate); 
}

static int
zlib_compress(char* dest, size_t* _destlen, 
	      const char* src, size_t _srclen)
{
	int ret;
	uLongf destlen = *_destlen;
	uLongf srclen = _srclen;
	
	ret = compress((Bytef *)dest, &destlen, (const Bytef *)src, srclen);
	if (ret != Z_OK){
		cl_log(LOG_ERR, "%s: compression failed",
		       __FUNCTION__);
		return HA_FAIL;
	}
	
	*_destlen = destlen;
	return HA_OK;

}

static int
zlib_decompress(char* dest, size_t* _destlen,
		const char* src, size_t _srclen)
{
	
	int ret;
	uLongf destlen = *_destlen;
	uLongf srclen = _srclen;
	
	ret = uncompress((Bytef *)dest, &destlen, (const Bytef *)src, srclen);
	if (ret != Z_OK){
		cl_log(LOG_ERR, "%s: decompression failed",
		       __FUNCTION__);
		return HA_FAIL;
	}
	
	*_destlen = destlen;	
	
	return HA_OK;
}

static const char*
zlib_getname(void)
{
	return "zlib";	
}

static struct hb_compress_fns zlibOps ={
	zlib_compress,
	zlib_decompress,
	zlib_getname,
};
