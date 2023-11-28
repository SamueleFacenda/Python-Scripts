#include <iostream>
#include "pila.h"
 
using namespace std;
 
static listaPila pila;
 
static bool pila_vuota () {
    return (pila == NULL);    
}
 
 
void pila_init() {
    pila = NULL;
}
 
 
bool pila_top (int &n) {
    
    bool risultatoOperazione;
    if (pila_vuota()) {
        risultatoOperazione = false;
    }
    else {
        n=pila->value;
        risultatoOperazione = true;
    }
    return risultatoOperazione;
}
 
 
bool pila_push (int n) {
 
    bool risultatoOperazione;
    listaPila nuovoNodo = new (nothrow) nodoPila;
    if (nuovoNodo==NULL) {
        risultatoOperazione = false;
    }
    else {
        nuovoNodo->value = n;
        nuovoNodo->next = pila;
        pila = nuovoNodo;
        risultatoOperazione = true;
    }
    return risultatoOperazione;
}
 
 
bool pila_pop () {
    
    bool risultatoOperazione;
    if (pila_vuota()) {
        risultatoOperazione = false;
    }
    else {
        listaPila primoNodo = pila;
        pila = pila->next;
        delete primoNodo;
        risultatoOperazione = true;
    }
    return risultatoOperazione;
}
 
void pila_deinit() {
    int tmp;
    while(pila_top(tmp)) {
        pila_pop();
    }
}
 
void pila_print() {
 
  if (!pila_vuota()) {
    listaPila nodoCorrente = pila;
    do {
      cout << nodoCorrente->value << endl;
      nodoCorrente = nodoCorrente->next;
    } while (nodoCorrente != NULL);
  }
}
