# vulns

## main function
-   scanf: buffer overflow

# functions

## is_dangerous_input

it detects following characters.
~`!@#$%^&\*()\_+-={}|[]\:";'<>?,./

# structs
## User
- 0x0 ~ 0x7: pronouns %7s
- 0x8 ~ 0x17: username %15s
- 0x18: admin_bit
# 脆弱性
- main関数でuser変数はint128_tとして定義されており、サイズが24バイトである。しかし、実際には25バイト分使われている。admin_bitは本来領域外である。
- main関数で1/2を入力するscanfに文字数制限がない。よってbofがある。死ぬほど長い文字列を入れると、ループの途中でもsigsegvで死ぬ。
- load_panel関数にfsbがある。
# アドレス情報
main関数のuser変数: 0x7fffffffeb40
main関数のinput_1変数: 0x7fffffffeb3e
# Exploitation
## アイデア
Userのadmin_bitを0以外にすれば、adminパネルを見れる。
## 設計
1. user変数をinput_1のoverflowで書き換える。
2. その次にadminパネルを見る。
3. fsbでスタック上のフラグを見る。 