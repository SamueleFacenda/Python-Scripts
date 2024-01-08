#include "pila.h"

static lista pila;

bool vuota () {
	return (pila == NULL);    
}



void init() {
	pila = NULL;
}


bool top (int &n) {
	
	bool risultatoOperazione;
	if (vuota()) {
		risultatoOperazione = false;
	}
	else {
		n=pila->value;
		risultatoOperazione = true;
	}
	return risultatoOperazione;
}


bool push (int n) {

	bool risultatoOperazione;
	lista nuovoNodo = new nodo;
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


bool pop () {
	
	bool risultatoOperazione;
	if (vuota()) {
		risultatoOperazione = false;
	}
	else {
		lista primoNodo = pila;
		pila = pila->next;
		delete primoNodo;
		risultatoOperazione = true;
	}
	return risultatoOperazione;
}

    
void deinit() {
	while (pop()) {
		;
	}
}
