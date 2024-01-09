#include <iostream>
#include "lista.h"

using namespace std;

bool empty(lista l) {
  return l == NULL;
}

int size(lista l) {
  if (empty(l)) {
    return 0;
  }
  int count = 0;
  nodo* p = l;
  do {
    count++;
    p = p->next;
  } while (p != l);
  return count;
}

bool insert_in(lista & l, char n[], int i) {
  bool res = false;
  nodo* p = new (nothrow) nodo;
  if (!p) {
    return false;
  }
  strcpy(p->nome, n);

  if (empty(l)) {
    l = p;
    l->next = l;
    res = true;
  } else if (size(l) == 1) {
    // lista con un solo nodo
    l->next = p;
    p->next = l;
    res = true;
  } else {
    i = i % size(l);
    for (int j = 0; j < i - 1; j++) {
      l = l->next;
    }
    nodo* followingNode = l->next;
    l->next = p;
    p->next = followingNode;
    res = true;
  }
  return res;
}

void print(const lista l) {
  if (empty(l)) {
    return;
  }
  nodo* p = l;
  do {
    cout << p->nome << "(" << p->colore << ") ";
    p = p->next;
  } while (p != l);
  cout << endl;
}

