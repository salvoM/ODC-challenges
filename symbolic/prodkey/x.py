import angr
import claripy
prog = angr.Project('./prodkey')


input_len = 30
input_str = claripy.BVS('flag', input_len*8)

initial_state = prog.factory.entry_state(
    stdin=input_str,
    add_options={angr.options.LAZY_SOLVES},
)

# for c in chars: #all chars are printable
#     initial_state.solver.add(c >=20, c <= 0x7e)

# We need to find an ACTIVATION-KEY
for byte in input_str.chop(8):
    initial_state.solver.add(byte >= ord('-'), byte <= ord('Z'))
    initial_state.solver.add(byte != ord('?'))
    initial_state.solver.add(byte != ord('@'))
    initial_state.solver.add(byte != ord('('))
    initial_state.solver.add(byte != ord('/'))
    initial_state.solver.add(byte != ord('='))



avoid = []
find =  0x400E58
sm = prog.factory.simgr(initial_state)
while len(sm.active) > 0:
    print("Hey, ", sm, sm.active)
    sm.explore(find=find,avoid=avoid, n=1)
    if sm.found:
        print(sm.found[0].posix.dumps(0)) # dump stdin content
        exit()
    else:   print("Not found...")