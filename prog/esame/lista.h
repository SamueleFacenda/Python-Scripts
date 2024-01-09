#ifndef LISTA_H
#define LISTA_H
#include <cstring>

// Implementazione di lista singolarmente concatenata circolare

enum color { nero = -1, rosso, verde, blu, giallo};

struct nodo {
  char nome[25];
  color colore = nero; // MR Inizializzazione di default, ignorare eventuale warning!
  nodo * next;
};
typedef nodo* lista;

int size(lista l);
bool empty(lista l);
bool insert_in(lista & l, char n[], int i);
void print(const lista l);


#endif