

import z3

input_chars = [z3.BitVec(f"c_{i}",8) for i in range(23)]

solver = z3.Solver()

solver.add( -30 * input_chars[0] + 139 * input_chars[1] + 93 * input_chars[11] + -100 * input_chars[13] + -189 * input_chars[18] + 189 * input_chars[5] + -50 * input_chars[8] + -249 * input_chars[7] + 229 * input_chars[15] + 172 * input_chars[4] + -221 * input_chars[22] + -92 * input_chars[9] + 76 * input_chars[19] + -142 * input_chars[3] + 218 * input_chars[2] + 91 * input_chars[20] - 236 * input_chars[21] - 129 * input_chars[16] + 137 * input_chars[12] - 124 * input_chars[17] + 84 * input_chars[14] - 2495 - 30 * input_chars[6] != 11 * input_chars[10] )


for c in input_chars:
    solver.add(c>=0x20, c<= 0x7e ) #printable

print(solver.check())
if solver.check():
    model = solver.model()
    #print(model)
    for c in input_chars:
        # print(c, chr(model.eval(c).as_long()))
        print(chr(model.eval(c).as_long()), end='')
