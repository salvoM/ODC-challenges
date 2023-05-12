# from pwn import *
import gdb
tentative_flag = 'flag{packer-djeidjeijderere}'
tentative_flag = 'flag{packer-djeidkeizz&-annoying}'

addr = '0x80492e5'
addr = '0x8049385'
addr_wp_check_pow = '0x0804a0a0'
addr_unpacker_call = '0x0804928a'
gdb.execute('file ./john ')
# gdb.Breakpoint("*" + addr_wp_check_pow, gdb.BP_WATCHPOINT)
gdb.Breakpoint("* "+ addr_unpacker_call)

# gdb.execute('hbreak *'+addr)
# o = gdb.execute('disassemble exit', to_string=True)

gdb.execute('run ' +  ' `echo \'' +tentative_flag + "\' ` ")

addr_check_fa = '0x080497db'


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