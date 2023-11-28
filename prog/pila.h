#ifndef PILA_H
#define PILA_H
 
struct nodoPila {
    int value;
    nodoPila* next;
};
typedef nodoPila* listaPila;
 
void pila_init();
bool pila_push(int);
bool pila_top(int &);
bool pila_pop();
void pila_deinit();
void pila_print();
 
#endif
 
