#include <stdio.h>
#include <stdlib.h>

int main(){
    srand(0x000a0000);
    int i;
    int tmp;
    for (i = 0; i < 0xff; i = i + 1) {
        tmp = rand();
        tmp = (char)tmp + (char)(tmp / 0x19) * -0x19 + 'A';
        printf("%c", tmp);
    }
}
