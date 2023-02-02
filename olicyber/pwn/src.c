#include <stdio.h>
#include <stdlib.h>

typedef struct {
    char name[64];
    int price;
    void (*foo)();
}Product;

void pennaRossa(){
    puts("Ecco a te una penna rossa!");
}

void pasticciotto(){
    puts("Ecco a te un pasticciotto alla crema!");
}

void flag(){
    char buffer[100];
    FILE* f = fopen("flag.txt", "r");
    fscanf(f, "%100s", buffer);
    fclose(f);
    puts(buffer);
}

void init(){
    setvbuf(stdin, NULL, _IOLBF, 0);
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
}

Product ps[] = {
    {"Penna rossa", 1, pennaRossa},
    {"Pasticciotto alla crema", 3, pasticciotto},
    {"flag", 1000000, flag}
};

int saldo = 10;

void clear(){
    while(getchar() != '\n');
}

void menu(){
    printf("Saldo corrente: %d€\n\n", saldo);

    for(int i = 0; i < sizeof(ps)/sizeof(Product); i++){
        printf("(%d) - %s: %d€\n", i+1, ps[i].name, ps[i].price);
    }
}

int main(int argc, char** args){
    init();
    puts("Benvenuto al super market!");

    int choice = 0;
    int amount = 0;
    int result;
    char altro;
    int cost;

    do{
        menu();
        do{
            printf("cosa vuoi comprare?\n> ");
            scanf("%d", &choice);
            clear();
        }while(choice < 1 || choice > 3);

        do{
            printf("Quante ne vuoi comprare?\n> ");
            result = scanf("%d", &amount);
            clear();
        }while(result != 1 || amount == 0);

        cost = ps[choice-1].price * amount;

        if(cost >= saldo){
            puts("Ci hai provato, mi dispiace!");
            exit(1);
        }
        else{
            saldo -= cost;
            ps[choice-1].foo();
        }

        printf("Altro? (s/n): ");
        scanf("%c", &altro);
        clear();
    }while(altro == 's');

    puts("Grazie per aver comprato da noi!");

    return 0;
}
