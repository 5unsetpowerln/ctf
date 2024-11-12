import angr
import sys

project = angr.Project("./ship.bin")
entry_state = project.factory.entry_state
simgr = project.factory.simgr(entry_state)


def check(state) -> bool:
    stdout_output = state.posix.dumps(sys.stdout.fileno)
    return b"Congratulations!" in stdout_output


simgr.explore(find=check)

if simgr.found:
    solution_state = simgr.found[0]
    print(solution_state.posix.dumps(sys.stdin.fileno()))

print("finish")
