

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

uint64_t extract_bit_from_mp3(FILE *input, int *end_of_stream) {
  int32_t buf = 0;
  // MP3ファイルから4バイトを読み取る
  int read_bytes = fread(&buf, 1, 4, input);

  if (read_bytes != 4) {
    *end_of_stream = 1;
    return 0;
  }

  // MPEGフレームヘッダの同期ワード（11ビット）を確認
  if ((buf & 0xffe00000) != 0xffe00000) {
    // 同期ワードが正しくない場合でも処理を続行（ここでは警告にとどめる）
    fprintf(stderr, "Warning: Possible invalid MPEG frame\n");
  }

  // ビットを抽出する（フレームの特定位置に埋め込まれているビットを仮定）
  return (buf >> 16) & 1;
}

void recover_string_from_mp3(FILE *input, char *recovered_str, int max_len) {
  int bit_count = 0;
  char current_char = 0;
  int end_of_stream = 0;

  for (int i = 0; i < max_len; i++) {
    for (int bit_pos = 0; bit_pos < 8; bit_pos++) {
      uint64_t bit = extract_bit_from_mp3(input, &end_of_stream);
      if (end_of_stream) {
        recovered_str[i] = '\0';
        return; // ストリームの終端に達したら終了
      }
      current_char |= (bit << bit_pos); // ビットを組み立てて1文字にする
    }
    recovered_str[i] = current_char;
    current_char = 0; // 次の文字のためにリセット
  }
  recovered_str[max_len - 1] = '\0'; // 最後にNULL終端
}

int main(int argc, char **argv) {
  if (argc != 3) {
    printf("Usage: %s [input_mp3_file] [output_flag]\n", argv[0]);
    return 1;
  }

  FILE *input_mp3 = fopen(argv[1], "rb");
  if (input_mp3 == NULL) {
    printf("Failed to open input MP3 file.\n");
    return 1;
  }

  char recovered_str[256]; // 復元する最大文字列の長さ
  recover_string_from_mp3(input_mp3, recovered_str, sizeof(recovered_str));

  fclose(input_mp3);

  // 復元した文字列を出力
  printf("Recovered string: %s\n", recovered_str);
  return 0;
}
