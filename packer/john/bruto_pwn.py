#!/usr/bin/python3
from pwn import *
# import gdb

tentative_flag = 'flag{packer-djeidkeizz&-annoying}'

addr_wp_check_pow   =    "0x0804a0a0"
addr_unpacker_call  =    "0x0804928a"

addr_ret_check_pow  =    "0x08049653" # 1 is good, 0 bad
addr_before_end     =    "0x08049821"

c1      =  "command 1" + "\n"
c1      +=  "hb *"+ addr_ret_check_pow +"\n"
c1      +=  "hb *"+ addr_before_end + "\n"
c1      +=  "set $val=0" + "\n"
c1      +=  "c" + "\n"
c1      +=  "disable breakpoint 1" + "\n"
c1      +=  "end" + "\n"


c2       =  "command 2" + "\n"
c2      +=  "set $val=$val+$eax" + "\n"
c2      +=  "end" + "\n"

c3       =  "command 2" + "\n"
c3      +=  "set logging on" + "\n"
c3      +=  "print $val" + "\n"
c3      +=  "set logging off" + "\n"
c3      +=  "c" + "\n"
c3      +=  "end" + "\n"

PROGRAM = "./john"
GDB_c   = ""

argv_1 = "`echo \'" +tentative_flag + "\' `"
# r = process(argv=[PROGRAM ,tentative_flag])
Gdb = gdb.debug(PROGRAM, api=True)
input("[!] Waiting for gdb...")

Gdb.execute(c1)


# input(WAIT)
"""
set $ipx=0
set $end=54
set $addr=0x8049385
while($ipx<54)
    print $ipx
    set {int}$addr=*$addr^0x42303042
    set $addr=$addr+4
    set $ipx=$ipx+1
end

local_7c 
0xffffce80:	0xa66fe7dd	0x0000001c	0x357afcf8	0x00000227
0xffffce90:	0x00000015	0x00000000	0x5c156c54	0x0000016c
0xffffcea0:	0xa66fe7dd	0x0000001c	0xe93ece66	0x0000009d
0xffffceb0:	0x5c156c54	0x0000016c	0x5c156c54	0x0000016c
0xffffcec0:	0xf3444241	0x00000756	0x4660a4c5	0x00000001
0xffffced0:	0xa66fe7dd	0x0000001c	0x00001000

"""