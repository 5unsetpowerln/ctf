import angr
import claripy

project = angr.Project("./test")

input1 = claripy.BVS("command", 5)
input2 = claripy.BVS("params", 0x100)

initial_state = project.factory.entry_state()

initial_state.posix.stdin.write(_=None, data=input1)
