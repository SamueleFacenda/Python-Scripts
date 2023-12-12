#include <iostream>


/* Inserire qui sotto la dichiarazione della funzione extract */
char* extract(char*, int = 0);
/* Inserire qui sopra la dichiarazione della funzione extract */

/* Solo di esempio, non fate assunzioni su questo valore */
const int DIM = 255;

int main(int argc, char ** argv) {
  char input_string[DIM+1];
  char * extracted;
  char answer;

  do {
    std::cout << "Inserire la stringa da controllare: ";
    std::cin >> input_string;

    extracted = extract(input_string);
    std::cout << "La stringa estratta e': " << extracted << std::endl;

    delete [] extracted;
    std::cout << "Si vuole inserire un'altra stringa? [*/n]";
    std::cin >> answer;
  } while (answer != '\0' && answer != 'N' && answer != 'n');
  return 0;
}

/* Inserire qui sotto la definizione della funzione estract */
char* extract(char* in, int count) {
    char *out;
    if (!in[0]){
        out = new char[count+1];
        out[count] = '\0';
    } else {
        if (in[0] == '@') {
            out = extract(in+1, count+1);
            out[count] = '@';
        } else
            out = extract(in+1, count);
    }
    return out;
}
/* Inserire qui sopra la definizione della funzione estract */
