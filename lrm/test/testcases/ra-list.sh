#!/bin/sh

awk '
NR==1 {num=$3;next}
{in_num++}
END{
	if( num!=in_num )
		print "ERROR: A mismatch in number of reported RAs!";
	else
		print "Cool. RA list passed.";
}
'
