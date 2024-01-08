#include <iostream>
#include "pila.h"

using namespace std;

int * collidiAsteroidi(int asteroidi[], int numeroAsteroidi, int & numeroAsteroidiRimasti);

int main() {
    
    // Potete modificare l'array di asteroidi (e la sua
    // dimensione) per testare la vostra soluzione
    int asteroidi [] = {-6, 10, 5, 8, -9};
    int numeroAsteroidi = 5;


    int numeroAsteroidiRimasti;
    int * asteroidiRimasti = collidiAsteroidi(asteroidi, numeroAsteroidi, numeroAsteroidiRimasti);


    // La stampa dell'array dinamico degli
    // asteroidi rimasti avviene nel main
    for (int i = 0; i < numeroAsteroidiRimasti ; i++) {
        cout << asteroidiRimasti[i] << " ";
    }
    cout << endl;

    // La deallocazione dell'array dinamico 
    // degli asteroidi rimasti avviene nel main
    delete[] asteroidiRimasti;
}


// Implementare la funzione sottostante come da consegna:
// - ritornare un'array di interi allocato dinamicamente che 
//   contenga lo stato degli asteroidi dopo tutte le collisioni
// - assegnare a 'numeroAsteroidiRimasti' il numero di elementi 
//   nell'array ritornato
int * collidiAsteroidi(int asteroidi[], int numeroAsteroidi, int & numeroAsteroidiRimasti) {
    init();
    bool collided, lastAlive;
    numeroAsteroidiRimasti = numeroAsteroidi;
    do {
        collided = false;
        numeroAsteroidi = numeroAsteroidiRimasti;
        for(int i=0; i<numeroAsteroidi -1; i++) {
        
            if (asteroidi[i]>0 && asteroidi[i+1]<0) {
                collided = true;
                if (asteroidi[i] > -asteroidi[i+1]) {
                    push(asteroidi[i]);
                    i++;
                    numeroAsteroidiRimasti--;
                    lastAlive = false;
                } else if (asteroidi[i] < -asteroidi[i+1]) {
                    numeroAsteroidiRimasti--;
                    lastAlive = true;
                } else {
                    i++;
                    numeroAsteroidiRimasti -= 2;
                    lastAlive = false;
                }
            } else {
                push(asteroidi[i]);
                lastAlive = true;
            }
            
        }
        if (lastAlive) 
            push(asteroidi[numeroAsteroidi-1]);
        
        for(int i=numeroAsteroidiRimasti-1; i>= 0; i--) {
            top(asteroidi[i]);
            pop();
        }
    } while (collided);
    
  numeroAsteroidiRimasti = numeroAsteroidi;
  int* out = new int[numeroAsteroidiRimasti];
  for(int i=0; i<numeroAsteroidiRimasti; i++) {
    out[i] = asteroidi[i];
  }   
  deinit();
  return out;

}
