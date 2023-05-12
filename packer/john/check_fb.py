
import z3
len_input = 12
input_chars = [z3.BitVec(f"c_{i}",8) for i in range(len_input)]
xor_chars = [ 0x0b, 0x4c, 0x0f, 0x00, 0x01, 0x16, 0x10, 0x07, 0x09, 0x38, 0x00, 0x00 ]

solver = z3.Solver()

solver.add(input_chars[0] == ord('&'))
for c in input_chars:
    solver.add(c>=0x20, c<= 0x7e ) #printable
    # solver.add(c != ord('}'))
    # solver.add(c != ord('&'))
    # solver.add(c != ord('#'))


for i in range(len_input-1):
    solver.add(input_chars[i] == input_chars[i+1]^xor_chars[i])
        

print(solver.check())
if solver.check():
    model = solver.model()
    #print(model)
    for c in input_chars:
        # print(c, chr(model.eval(c).as_long()))
        print(chr(model.eval(c).as_long()), end='')