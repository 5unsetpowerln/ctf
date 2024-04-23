undefined8 main(void)

{
  undefined copyDest [40];
  int calcOption;
  int numberCalc;
  void *heapArea;
  int calcCount;
  
  numberCalc = 0;
  setvbuf((FILE *)stdin,(char *)0x0,2,0);
  setvbuf((FILE *)stdout,(char *)0x0,2,0);
  print_motd();
  printf("Expected number of calculations: ");
  __isoc99_scanf(&DAT_00494214,&numberCalc);
  handle_newline();
  if ((numberCalc < 256) && (3 < numberCalc)) {
    heapArea = malloc((long)(numberCalc * 4));
    for (calcCount = 0; calcCount < numberCalc; calcCount = calcCount + 1) {
      print_menu();
      __isoc99_scanf(&DAT_00494214,&calcOption);
      handle_newline();
      if (calcOption == 1) {
        adds();
        *(undefined4 *)((long)calcCount * 4 + (long)heapArea) = DAT_006c4a88;
      }
      else if (calcOption == 2) {
        subs();
        *(undefined4 *)((long)calcCount * 4 + (long)heapArea) = DAT_006c4ab8;
      }
      else if (calcOption == 3) {
        muls();
        *(undefined4 *)((long)calcCount * 4 + (long)heapArea) = DAT_006c4aa8;
      }
      else if (calcOption == 4) {
        divs();
        *(undefined4 *)((long)calcCount * 4 + (long)heapArea) = DAT_006c4a98;
      }
      else {
        if (calcOption == 5) {
          memcpy(copyDest,heapArea,(long)(numberCalc * 4));
          free(heapArea);
          return 0;
        }
        puts("Invalid option.\n");
      }
    }
    free(heapArea);
  }
  else {
    puts("Invalid number.");
  }
  return 0;
}

