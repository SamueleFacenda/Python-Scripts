#ifndef PILA_H
#define PILA_H

#include <iostream>
using namespace std;


struct nodo {
	int value;
	nodo* next;
};
typedef nodo* lista;

void init();
void deinit();
bool push(int);
bool top(int &);
bool pop();
bool vuota();


#endif
