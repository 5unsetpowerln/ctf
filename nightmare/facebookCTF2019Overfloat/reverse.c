void chart_course(long param_1)

{
  int diff;
  double dVar1;
  char input[104];
  float local_10;
  uint count;

  count = 0;
  do {
    if ((count & 1) == 0) {
      diff = (int)count / 2;
      printf("LAT[%d]: ",
             (ulong)(uint)(diff +
                           ((diff / 10 +
                             ((int)(count - ((int)count >> 0x1f)) >> 0x1f)) -
                            (diff >> 0x1f)) *
                               -10));
    } else {
      diff = (int)count / 2;
      printf("LON[%d]: ",
             (ulong)(uint)(diff +
                           ((diff / 10 +
                             ((int)(count - ((int)count >> 0x1f)) >> 0x1f)) -
                            (diff >> 0x1f)) *
                               -10));
    }
    fgets(input, 100, stdin);
    diff = strncmp(input, "done", 4);
    if (diff == 0) {
      if ((count & 1) == 0) {
        return;
      }
      puts("WHERES THE LONGITUDE?");
      count = count - 1;
    } else {
      dVar1 = atof(input);
      local_10 = (float)dVar1;
      memset(input, 0, 100);
      *(float *)(param_1 + (long)(int)count * 4) = local_10;
    }
    count = count + 1;
  } while (true);
}
