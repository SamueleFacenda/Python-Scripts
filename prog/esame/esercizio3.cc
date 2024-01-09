#include <iostream>
#include "lista.h"

using namespace std;

const int POS_AL_SECONDO = 2;
const int DIM_COLORI = 3;
const int MAX_BAMBINI = 7;

const char* nomi[26] = {"Tommaso", "Alice", "Andrea", "Madison", "Emanuele", "Nora", "Fabio", "Eleanor", "Filippo", "Scarlett", "Vittorio", "Penelope", "Michele", "Aria", "Giacomo", "Stella", "Emanuela", "Luna", "Cristiano", "Evelyn", "Claudio", "Abigail", "Greta", "Henry", "Alexandra", "Diego"};
const color colori[DIM_COLORI] = {verde, blu, giallo};

// Inserire QUI sotto la dichirazione delle funzioni coloraPartecipante e cerca.
lista cerca(lista, char[]);
lista coloraPartecipante(lista, int, int);
// Inserire QUI sopra la dichirazione delle funzioni coloraPartecipante e cerca.

int main() {
    lista cerchio = NULL;

    unsigned int seed = time(NULL);
    // Commentare la riga sotto per non avere sempre lo stesso seed
    //seed = 1703945587;
    //seed = 1704400514;
    std::cout << "Seed: " << seed << std::endl;
    srand(seed);
    
    int numero_bambini = rand() % MAX_BAMBINI + 2;
    for (int i = 0; i < numero_bambini; i++) {
        char* nome = (char*)nomi[rand() % 18];
        if (cerca(cerchio, nome) == NULL) {
            insert_in(cerchio, nome, 0);
        } else {
            i--;
        }
    }

    cout << "Ci sono " << size(cerchio) << " bambini nella lista." << endl;
    print(cerchio);

    int i = 0;
    int durata;
    bool finished = false;

    while (!empty(cerchio) && !finished) {
        cout << "-------------------------------------------------------------" << endl;
        cout << "Giro numero " << ++i << endl;
        
        cout << "La canzone durerà per " << (durata = rand() % 60 + 10) << " secondi." << endl;

        int sedia_rimossa = rand() % size(cerchio);
        cout << "Fermo il bambino alla sedia numero " << sedia_rimossa << "." << endl;

        lista eliminato = coloraPartecipante(cerchio, durata, sedia_rimossa);

        if (eliminato != NULL) {
            cout << eliminato->nome << " ha ricevuto il colore " << eliminato->colore << endl;
        } else {
            cout << "Tutti i bambini hanno un colore. Ho finito." << endl;
            finished = true;
        }
        print(cerchio);
    }

    // Controllo che non ci siano colori adiacenti
    for (lista m = cerchio; m != cerchio; m = m->next) {
        if (m->colore == m->next->colore) {
            cout << "ERROR: colori adiacenti!" << endl;
            exit(1);
        }
        if (m->colore == nero) {
            cout << "ERROR: C'è un colore nero!" << endl;
            exit(1);
        }
    }

    cout << "-------------------------------------------------------------" << endl;
    cout << "Tutti i bambini hanno un colore. Ho finito." << endl;

    return 0;
}

// Inserire QUI sotto la definizione delle funzioni coloraPartecipante e cerca.
lista cerca(lista nodo, char nome[]) {
    if (!nodo) 
        return NULL;

    if (strcmp(nodo->nome, nome) == 0)
        return nodo;
    
    lista curr;
    for(curr = nodo->next; curr != nodo && strcmp(curr->nome, nome); curr=curr->next);

    return strcmp(curr->nome, nome) ? NULL : nodo;
}

lista coloraPartecipante(lista cerchio, int durata, int sediaRimossa) {
    if (!cerchio)
        return NULL;

    int pos = (durata * POS_AL_SECONDO + sediaRimossa) % size(cerchio);
    lista eliminated = cerchio;
    for(int i=0; i < pos; eliminated = eliminated->next, i++);

    // new loop to get the previous color and latest non-colored child
    // I do this every time just to be safe against edge-cases and avoid a lot of ifs
    lista latestNonColored = eliminated->colore == nero ? eliminated : NULL;
    color prevColor = eliminated->colore, latestNonColoredPrevColor = eliminated->colore;
    for(lista curr=eliminated->next; curr != eliminated; curr=curr->next) {
        if (curr->colore == nero) {
            latestNonColoredPrevColor = prevColor;
            latestNonColored = curr;
        }
        prevColor = curr->colore;
    }

    if (eliminated->colore != nero) {
        eliminated = latestNonColored;
        prevColor = latestNonColoredPrevColor;
    }

    if (eliminated != NULL) {
        // assign a color
        do {
            eliminated->colore=color(rand()%5 -1);
        } while (eliminated->colore == prevColor 
                || eliminated->colore == eliminated->next->colore);
    }

    return eliminated;
}