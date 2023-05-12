from pwn import *
import os
# import gdb

#flag{packer-4j3-1yzzzzzzzzzzzzzz}
char_to_guess = 10
charset = "0143123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\'()*+,-./:;<=>?@[\\]^_"
flag = "flag{packer"
base_count = 1
for i in range(char_to_guess):
    for c in charset:
        #Setting the new tentative
        test_flag = flag + c
        with open('./tentative_flag', 'w') as f:
            t = test_flag.ljust(0x20,"y")+"}"
            
            # print(test_flag)
            f.write(t)

        #cleaning the previous output
        if os.path.exists("./gdb.txt"):
            os.remove('./gdb.txt')
        
        #running the actual test
        with context.local(log_level='ERROR'):
            r = process(['gdb', '-q', '-x', 'gdb_script'])
            o = r.recvuntil("\x1b[1;31mLoser\n\x1b[0m")
            print(".", end="")
            r.close()
        
        #retrieving the output
        with open("./gdb.txt", 'r') as f:
            lines = f.read().split("\n")
            count = len(lines) - 1 # empty new line at the end
            if len(lines) != len(set(lines)):
                print(f"mmh, weird: {c}")
                count = base_count
        # print(count, base_count)

        #checking the output
        if count > base_count:
            #if this is true it means that the additional char was correct
            flag += c
            base_count += 1
            #If so I start guessing the next char
            break

        #check if i checked all the charset for this position
        #if so, there is a problem
        if c == charset[-1:]:
            print("I think something is broken")
            exit()
    print("\n"+flag)

print(f"FLAG FOUND: {flag}")


    # if test_flag.count('z') != 19-i and i != 5:
    #     print(test_flag, test_flag.count('z'), i )
    #     print("Bruteforce failed! :(")
    #     break