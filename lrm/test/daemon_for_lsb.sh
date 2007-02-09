#!/bin/bash
echo $$ > /tmp/.daemon_testlsb_script_pid
while [ 1==1 ] ; do
    echo test > /dev/null;
done
exit 0
