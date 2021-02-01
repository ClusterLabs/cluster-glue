#!/usr/bin/env python3


#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, see <http://www.gnu.org/licenses/>
#

import sys
import socket
from http.client import *
from time import sleep


argv = sys.argv


try:
        host = argv[1].split('.')[0]+'-rm'
        cmd = argv[2]
except IndexError:
        print("Not enough arguments")
        sys.exit(1)


login = [ b'<RIBCL VERSION="1.2">',
          b'<LOGIN USER_LOGIN="Administrator" PASSWORD="********">' ]


logout = [ b'</LOGIN>', b'</RIBCL>' ]


status = [ b'<SERVER_INFO MODE="read">', b'<GET_HOST_POWER_STATUS/>',
           b'</SERVER_INFO>' ]


reset = [ b'<SERVER_INFO MODE="write">', b'<RESET_SERVER/>', b'</SERVER_INFO>' ]


off = [ b'<SERVER_INFO MODE = "write">', b'<SET_HOST_POWER HOST_POWER  = "N"/>',
          b'</SERVER_INFO>' ]


on = [ b'<SERVER_INFO MODE = "write">', b'<SET_HOST_POWER HOST_POWER  = "Y"/>',
          b'</SERVER_INFO>' ]


todo = { 'reset':reset, 'on':on, 'off':off, 'status':status }


acmds=[]
try:
        if cmd == 'reset' and host.startswith('gfxcl'):
                acmds.append(login + todo['off'] + logout)
                acmds.append(login + todo['on'] + logout)
        else:   
                acmds.append(login + todo[cmd] + logout)
except KeyError:
        print("Invalid command: "+ cmd)
        sys.exit(1)


try:
        for cmds in acmds:


                c=HTTPSConnection(host)
                c.send(b'<?xml version="1.0"?>\r\n')
                c.sock.recv(1024)


                for line in cmds:
                        c.send(line+b'\r\n')
                        c.sock.recv(1024)


                c.close()
                sleep(1)


except socket.gaierror as msg:
        print(msg)
        sys.exit(1)
except socket.error as msg:
        print(msg)
        sys.exit(1)
