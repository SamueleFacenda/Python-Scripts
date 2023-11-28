#ifndef CODA_H
#define CODA_H
 
struct nodoCoda {
    int value;
    nodoCoda* next;
};
typedef nodoCoda* listaCoda;
 
struct coda {
    listaCoda tail;
    listaCoda head;
};
 
void coda_init();
bool coda_enqueue(int);
bool coda_first(int &);
bool coda_dequeue();
void coda_deinit();
void coda_print();
 
#endif
 
