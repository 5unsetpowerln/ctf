# Secret Sequence (ja)

## Solution

<!-- Writeupに相当するドキュメントを書いてください。 -->

この問題では、Twofishと呼ばれる暗号方式を自分で実装しており、それを用いてフラグを暗号化しています。問題文にある通り、実装が正しくないので、それを利用してFlagを特定することが出来ます。

問題文には「公式サイトの Test Vectors に載ってる Known Answer Test と暗号化の結果が一致しない」とあります。[公式サイト](https://www.schneier.com/academic/twofish/)の、Test Vectorsに載っている、KEYSIZE=128のものについて実際に暗号化をすると、`KEY=00000000000000000000000000000000,PT=00000000000000000000000000000000`の場合と、`KEY=00000000000000000000000000000000,PT=9F589F5CF6122C32B6BFEC2F2AE8C35A`の場合には正しく暗号化できているが、それ以外の、`KEY=00000000000000000000000000000000`でない場合については正しく暗号化できていないことがわかります。この情報を元に、実装で秘密鍵がどのように扱われているのかに注目してコードを読んでいきます。

秘密鍵に注目してコードを追っていくと、ファイルの165,166行目、`key_schedule`関数内に
```Python
    keys = np.full(7,b"")
    keys[0] = key
```
とあるのが見つかります。ここで変数`keys`は`np.full(7,b"")`によって初期化されています。numpyではこれは長さ1のバイト列の配列となるため、ここに長さ2以上のバイト列を代入した場合、先頭以外の文字は消えます。つまり、`keys[0]`には`key`ではなく`key[0]`が代入されます。`key[0]`としてありうる値は高々256通りなので、これらすべてを秘密鍵として暗号文を復号し、その結果がフラグの形式に合致するものがフラグです。

## Flag

``TSGCTF{P3ople_li|<e_w4$+3,_I_|<|\|o\/\/._If_I_wa$_g0i|\|g_t0_ac+u4lly_use_i+,_I_shoul|)_not_h4ve_i|\/|ple|\/|e|\|ted_+|-|3_(i|*he|2_0|\|_|\/|`/_own.}``