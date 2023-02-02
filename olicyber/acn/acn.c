undefined8 main(int param_1,long param_2){
  int iVar1;
  byte local_57 [15];
  undefined8 local_48;
  undefined3 local_40;
  undefined5 uStack_3d;
  undefined3 uStack_38;
  undefined8 local_35;
  undefined8 local_28;
  undefined8 local_20;
  byte local_d;
  int local_c;
  
  if (param_1 == 2) {
    local_28 = 0xe1b4937092b3430;
    local_20 = 0x190915441d;
    local_48 = 0x6975797472657771;
    // e1b4937092b34301909154
    // 697579747265777161706f
    // iuytrewqapohgfdslkjmnbvcxz
    local_40 = 0x61706f;
    uStack_3d = 0x6867666473;
    uStack_38 = 0x6c6b6a;
    local_35 = 0x6d6e627663787a;
    for (local_c = 0; local_c < 0xd; local_c = local_c + 1) {
      local_d = *(byte *)((long)&local_48 + (long)local_c) ^
                *(byte *)((long)&local_28 + (long)local_c);
      local_57[local_c] = local_d;
    }
    local_57[local_c] = 0;
    fflush(stdout);
    iVar1 = strcmp((char *)local_57,*(char **)(param_2 + 8));
    printf("Risposta: %s\n",local_57);
    if (iVar1 == 0) {
      printf("Congratulazioni!");
    }
    else {
      printf("Ritenta!");
    }
    fflush(stdout);
  }
  else {
    printf("Ritenta!");
  }
  return 0;
}