#include <iostream>
#include <cstdlib>

struct nodo {
    int valore;
    nodo* nodoPrecedente;
    nodo* nodoSuccessivo;
};
typedef nodo* lista;

using namespace std;


void inizializza (int arrayDiInteri [], int dimensioneArray);
void stampaLista (lista nodoCorrente);

// Inserire qui la dichiarazione di "creaLista" e "rimuoviNodiAlternati"
lista  creaLista(int[], int);
lista rimuoviNodiAlternati(lista);
bool rimuoviUnNodoAlternato(lista&);
void deallocaLista(lista);

int main() { 

    // Non modificare la funzione "main". Si può invece (temporaneamente)
    // modificare la funzione "inizializza" per dare dei valori specifici
    // agli elementi dell'array "arrayDiInteri" ai fini di debugging.

    int dimensioneArray = 8;
    int arrayDiInteri[dimensioneArray];
    inizializza(arrayDiInteri, dimensioneArray);

    lista nodoIniziale = creaLista(arrayDiInteri, dimensioneArray);

    cout << "Lista iniziale: ";
    stampaLista(nodoIniziale);

    nodoIniziale = rimuoviNodiAlternati(nodoIniziale);

    cout << "Risultato: ";
    stampaLista(nodoIniziale);
    deallocaLista(nodoIniziale);

    return 0;
}

void inizializza (int arrayDiInteri [], int dimensioneArray) {
    
    // Si può (temporaneamente) modificare la funzione "inizializza" 
    // per dare dei valori specifici agli elementi dell'array "arrayDiInteri" 
    // ai fini di debugging. Ricordarsi tuttavia di ristabilire il codice
    // originale prima di consegnare l'esercizio.

    srand(time(NULL));

    for (int i = 0 ; i < dimensioneArray ; i++) {
        arrayDiInteri[i] = i % 3;
    }

    int contatore = dimensioneArray;
    while (contatore > 1) {
       int indice = rand() % contatore;
       contatore--;
       int temp = arrayDiInteri[contatore];
       arrayDiInteri[contatore] = arrayDiInteri[indice];
       arrayDiInteri[indice] = temp;
    }
}

void stampaLista(nodo* nodoCorrente) {

    // Non modificare la funzione "stampaLista"

    while (nodoCorrente != NULL) {
        cout << nodoCorrente->valore << " ";
        nodoCorrente = nodoCorrente->nodoSuccessivo;
    }
    cout << endl;
}


// Inserire qui la definizione di "creaLista", "rimuoviNodiAlternati" e di eventuali altre funzioni ausiliarie
lista creaLista(int arr[], int len) {
    if (!len)
        return nullptr;
        
    lista out = new nodo{arr[0], nullptr, nullptr};
    lista last = out, tmp;
    for(int i=1; i<len; i++) {
        tmp = new nodo{arr[i], last, nullptr};
        last->nodoSuccessivo = tmp;
        last = tmp;
    }
    return out;
}

void deallocaLista(lista l) {
    if (l) {
        deallocaLista(l->nodoSuccessivo);
        delete l;
    }
}

lista rimuoviNodiAlternati(lista l) {
    lista out = l;
    while(rimuoviUnNodoAlternato(out));
    return out;
}

bool rimuoviUnNodoAlternato(lista &l) {
    if (!l)
        return false;
    if (!l->nodoSuccessivo)
        return false;
    if (!l->nodoSuccessivo->nodoSuccessivo)
        return false;
    
    lista first, second, third;
    
    for (lista current = l->nodoSuccessivo; current->nodoSuccessivo; current = current->nodoSuccessivo) {
        if (current->nodoSuccessivo->valore == current->nodoPrecedente->valore) {
            first = current->nodoPrecedente;
            second = current;
            third = current->nodoSuccessivo;
            
            second->nodoSuccessivo = third->nodoSuccessivo;
            if (third->nodoSuccessivo)
                third->nodoSuccessivo->nodoPrecedente = second;
                
            second->nodoPrecedente = first->nodoPrecedente;
            if (first->nodoPrecedente)
                first->nodoPrecedente->nodoSuccessivo = second;
                
            if (!first->nodoPrecedente)
                // first was the list start
                l = second;
                
            delete first;
            delete third;
        
            return true;
        }
    }

    return false;    
}
