"""
This script tries to solve the problem with different
sets of constraints by creating and executing a child script
-> This is not the correct solution (and does not produce the flag)
because the constraints need to hold simultaneously. 
I'm leaving it here just cause i liked this child script idea
"""
import os
prog_1 = """

import z3

input_chars = [z3.BitVec(f"c_{i}",8) for i in range(23)]

solver = z3.Solver()

"""

prog_2 = """


for c in input_chars:
    solver.add(c>=0x20, c<= 0x7e ) #printable

print(solver.check())
if solver.check():
    model = solver.model()
    #print(model)
    for c in input_chars:
        # print(c, chr(model.eval(c).as_long()))
        print(chr(model.eval(c).as_long()), end='')
"""

constr_f = open("constraints", 'r')
constr = constr_f.read()
constr_f.close()



f = open("a.py",'w') # Child script with the current set of constraints

c = ""
i = 0

for line in constr.split("\n"):
    
    if line == "#":
        f = open("a.py",'w')
        c = c.replace("  ", "")
        f.write(prog_1+c+prog_2)
        # print(prog_1+c+prog_2)
        f.close()
        print(f"\nExecuting script n.{i}")
        os.system('python3 a.py')
        c = ""
        i +=1
    else:
        c += line
    
