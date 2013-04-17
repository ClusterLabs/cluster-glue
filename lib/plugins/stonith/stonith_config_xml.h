/*
 * stonith_config_xml.h: common macros easing the writing of config
 *			 XML for STONITH plugins.  Only a STONITH
 * 			 plugin should include this header!
 *
 * Copyright (C) International Business Machines Corp., 2005 
 * Author: Dave Blaschke <debltc@us.ibm.com>
 * Support: linux-ha@lists.linux-ha.org
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
#ifndef _STONITH_CONFIG_XML_H
#define _STONITH_CONFIG_XML_H

/*
 * The generic constants for XML
 */

/* <parameters>?</parameters> */
#define XML_PARAMETERS_BEGIN "<parameters>"
#define XML_PARAMETERS_END "</parameters>"

/* <parameter name="ipaddr" unique="?">?<content type="string" /></parameter> */
#define XML_PARAMETER_BEGIN(name,type,req,uniq) \
	"<parameter name=\"" name "\" unique=\"" uniq "\" required=\"" req "\">" \
	"<content type=\"" type "\" />\n"
#define XML_PARAMETER_END "</parameter>\n"

/* <shortdesc lang="en">?</shortdesc> */
#define XML_PARM_SHORTDESC_BEGIN(lang) \
	"<shortdesc lang=\"" lang "\">\n"
#define XML_PARM_SHORTDESC_END "</shortdesc>\n"

/* <longdesc lang="en">?</longdesc> */
#define XML_PARM_LONGDESC_BEGIN(lang) \
	"<longdesc lang=\"" lang "\">\n"
#define XML_PARM_LONGDESC_END "</longdesc>\n"

/*
 * The short and long descriptions for the few standardized parameter names;
 * these can be translated by appending different languages to these constants
 * (must include XML_PARM_****DESC_BEGIN(), the translated description, and
 * XML_PARM_****DESC_END for each language)
 */
#define XML_HOSTLIST_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	"Hostlist" \
	XML_PARM_SHORTDESC_END

#define XML_HOSTLIST_LONGDESC \
	XML_PARM_LONGDESC_BEGIN("en") \
	"The list of hosts that the STONITH device controls" \
	XML_PARM_LONGDESC_END

#define XML_IPADDR_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	"IP Address" \
	XML_PARM_SHORTDESC_END

#define XML_IPADDR_LONGDESC \
	XML_PARM_LONGDESC_BEGIN("en") \
	"The IP address of the STONITH device" \
	XML_PARM_LONGDESC_END

#define XML_LOGIN_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	"Login" \
	XML_PARM_SHORTDESC_END

#define XML_LOGIN_LONGDESC \
	XML_PARM_LONGDESC_BEGIN("en") \
	"The username used for logging in to the STONITH device" \
	XML_PARM_LONGDESC_END

#define XML_PASSWD_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	"Password" \
	XML_PARM_SHORTDESC_END

#define XML_PASSWD_LONGDESC \
	XML_PARM_LONGDESC_BEGIN("en") \
	"The password used for logging in to the STONITH device" \
	XML_PARM_LONGDESC_END

#define XML_COMMUNITY_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	"SNMP Community" \
	XML_PARM_SHORTDESC_END

#define XML_COMMUNITY_LONGDESC "" \
	XML_PARM_LONGDESC_BEGIN("en") \
	"The SNMP community string associated with the STONITH device" \
	XML_PARM_LONGDESC_END

#define XML_TTYDEV_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	"TTY Device" \
	XML_PARM_SHORTDESC_END

#define XML_TTYDEV_LONGDESC "" \
	XML_PARM_LONGDESC_BEGIN("en") \
	"The TTY device used for connecting to the STONITH device" \
	XML_PARM_LONGDESC_END

/* 
 * Complete parameter descriptions for the few standardized parameter names
 */
#define XML_HOSTLIST_PARM \
	XML_PARAMETER_BEGIN(ST_HOSTLIST, "string", "1", "0") \
	  XML_HOSTLIST_SHORTDESC \
	  XML_HOSTLIST_LONGDESC \
	XML_PARAMETER_END

#define XML_IPADDR_PARM \
	XML_PARAMETER_BEGIN(ST_IPADDR, "string", "1", "0") \
	  XML_IPADDR_SHORTDESC \
	  XML_IPADDR_LONGDESC \
	XML_PARAMETER_END

#define XML_LOGIN_PARM \
	XML_PARAMETER_BEGIN(ST_LOGIN, "string", "1", "0") \
	  XML_LOGIN_SHORTDESC \
	  XML_LOGIN_LONGDESC \
	XML_PARAMETER_END

#define XML_PASSWD_PARM \
	XML_PARAMETER_BEGIN(ST_PASSWD, "string", "1", "0") \
	  XML_PASSWD_SHORTDESC \
	  XML_PASSWD_LONGDESC \
	XML_PARAMETER_END

#define XML_COMMUNITY_PARM \
	XML_PARAMETER_BEGIN(ST_COMMUNITY, "string", "1", "0") \
	  XML_COMMUNITY_SHORTDESC \
	  XML_COMMUNITY_LONGDESC \
	XML_PARAMETER_END

#define XML_TTYDEV_PARM \
	XML_PARAMETER_BEGIN(ST_TTYDEV, "string", "1", "0") \
	  XML_TTYDEV_SHORTDESC \
	  XML_TTYDEV_LONGDESC \
	XML_PARAMETER_END

#endif
