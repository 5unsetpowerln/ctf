import angr
import sys

project = angr.Project("./drone.bin")

initial_state = project.factory.entry_state()
simulation = project.factory.simgr(initial_state)

# good_addr = 0x401DE5
# simulation.explore(find=good_addr)


def check_memory_change(state):
    current_value = state.memory.load(0x4067E8, 4)
    if state.solver.satisfiable(extra_constraints=[current_value != 0]):
        return True
    return False


simulation.explore(find=check_memory_change)


if simulation.found:
    solution_state = simulation.found[0]
    print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
    print("couldn't find")
