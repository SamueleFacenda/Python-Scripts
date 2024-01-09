#include <iostream>
#include <iomanip>
#include <cstdlib>

void copy_array(char *src, char *dst, int n) {
    for (int i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

// Inserire qui la dichiarazione della funzione codici
char** codici(int, int&);
// Inserire qui sopra la dichiarazione della funzione codici_aux

// NON MODIFICARE IL MAIN
int main(int argc, char **argv) {
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " #num" << std::endl;
        exit(1);
    }
    int nb = atoi(argv[1]);

    int max;
    char **res = codici(nb, max);

    std::cout << "Grey codes for " << nb << " bits:" << std::endl;
    for (int i = 0; i < max; i++) {
        std::cout << std::setw(3) << i << ": ";
        for (int j = 0; j < nb; j++) {
            std::cout << res[i][j];
        }
        delete [] res[i];
        std::cout << std::endl;
    }
    delete [] res;
    return 0;
}
// NON MODIFICARE IL MAIN

// Inserire qui sotto eventuali definizioni di funzioni ausiliarie
void copyGrayLine(char** out, int halfIndex, int i, int len) {
    //half is the index of the line below the half (greater)
    if (i==halfIndex) 
        return;

    copy_array(out[i], out[halfIndex+halfIndex-i-1], len);
    out[i][len] = '0';
    out[halfIndex+halfIndex-i-1][len] = '1';
    copyGrayLine(out, halfIndex, i+1, len);
}
void fillGray(char** out, int size) {
    if (size==1) {
        out[0][0] = '0';
        out[1][0] = '1';
    } else {
        fillGray(out, size-1);
        // now copy it below and add 0 or 1
        copyGrayLine(out, 1<<(size-1), 0, size-1);
    }
}
void allocateRec(char** out, int i, int size) {
    if (i<0)
        return;
    out[i] = new char[size];
    allocateRec(out, i-1, size);
}
// Inserire qui sopra eventuali definizioni di funzioni ausiliarie

// Inserire qui sotto la definizione della funzione codici
char** codici(int size, int &max) {
    // uso l'ordine inverso nella matrice, rimane un codice di gray valido (aggiungo le colonne dopo)
    max = 1<<size;
    std::cout << "max: " << max << std::endl;
    char **out = new char*[max];
    allocateRec(out, max-1, size);
    fillGray(out, size);
    return out;
}
// Inserire qui sopra la definizione della funzione codici