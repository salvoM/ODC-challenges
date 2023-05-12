#!/usr/bin/python3
"""
Once I reversed the binary I wrote this simple script just to
generate the characters of the flag

"""
flag = 'flag{'

babuzz = 'babuzzbabuzzb'
magic0 = '\x1b\x51\x17\x2a\x1e\x4e\x3d\x10\x17\x46\x49\x14\x3d'

for i in range(0xd):
    flag += chr(ord(babuzz[i]) ^ ord(magic0[i]))

magic1 = '\xeb\x51\xb0\x13\x85\xb9\x1c\x87\xb8\x26\x8d\x07'
print(len(magic1))
temp   = 187

for i in range(0xc):
    a = ord(magic1[i]) - temp
    print(ord(magic1[i]) - temp)
    if(a < 0): a+=256
    flag += chr(a)
    temp  = ord(magic1[i])
    
flag += '}'
print(flag)