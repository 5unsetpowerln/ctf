from sympy import symbols, Eq, solve

# inputを定義
input_var = symbols("input")

# 与えられた合同式
enc = 97 + (200 + 100 + input_var) % 26

# enc = 97 + (A + B + input) % 26 という式を作成
equation = Eq(enc, 97 + (100 + 200 + input_var) % 26)

# 方程式を解く
solution = solve(equation, input_var)

# 結果を表示
print("inputの解:", next(solution))
