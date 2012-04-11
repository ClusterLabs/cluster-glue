#!/bin/sh

gawk -v many="$1" '
BEGIN{XMLLINT="xmllint --noout -";}
function chkoutput(ra) {
	if( ra=="" ) return;
	if( close(XMLLINT) ) # we need gawk for this
		print "xmllint reported error in RA:",ra;
}
many=="many" && /^[a-zA-Z][^:]*:[a-zA-Z0-9]+$/ {
	chkoutput(ra);
	ra=$0;
	next;
}
{ print | XMLLINT }
END{
	if( many!="many" )
		chkoutput("noname");
}
'
