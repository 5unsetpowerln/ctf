# 処理の流れ
command バッファを0で初期化
argsバッファを0で初期化

readでcommandに5文字読み込む
readでargsに0x100文字読み込む

この処理の間で、動的にジャンプ先を計算しているところがあったはず。

commandが"RECD"だったら、次に進む
argsが1~300だったら、次に進む

0x40175aを呼び出す
	argsに合わせた出力をする
0x401847を呼び出す
	readで0x7fffffffdf20に0x3e8読み込む
	saved file \<input\<と表示する

これの繰り返し