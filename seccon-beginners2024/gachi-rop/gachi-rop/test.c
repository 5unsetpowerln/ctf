#include <dirent.h>
#include <stdio.h>
int main() {
  DIR *dir;
  struct dirent *entry;
  // ディレクトリを開く
  dir = opendir("/home/ryohz/ctf/seccon-beginners2024/gachi-rop/gachi-rop/");
  if (dir == NULL) {
    printf("ディレクトリを開けませんでした。\n");
    return 1;
  }
  // ディレクトリ内のファイルを順番に表示する
  entry = readdir(dir);
  printf("%s\n", entry->d_name);
  // ディレクトリを閉じる
  closedir(dir);
  return 0;
}
