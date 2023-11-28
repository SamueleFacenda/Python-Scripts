#include <iostream>
#include <cstdlib>
#include <fstream>
#include "lib/pila.h"
#include "lib/utils.hpp"
#include "lib/coda.h"
// # define int unsigned long long

using namespace std;

void checkArgs(int req, int argc);

void readIntToQueue(char* name) {
    fstream in;
    in.open(name, ios::in);
    if (in.fail()) {
        exit(1);
    }
    int tmp;
    pila_init();
    while(!in.eof()){
        in >> tmp;
        if (!in.fail())
            pila_push(tmp);
    }
}

void putQueueInFile(char* name) {
    fstream out;
    out.open(name, ios::out);
    if (out.fail()) {
        exit(1);
    }
    int tmp;
    if (!pila_top(tmp))
        return;
    do {
        pila_top(tmp);
        out << tmp << endl;
    } while(pila_pop());
    pila_deinit();
}

bool areBalanced(char* in) {
    pila_init();
    for(int i=0; in[i]; i++) {
        switch(in[i]) {
            case '(':
                pila_push(0);
                break;
            case ')':
                if (!pila_pop())
                    return false;
                break;
        }
    }
    bool out = !pila_pop();
    pila_deinit();
    return out;
}

void invertiPila() {
    coda_init();
    int tmp;
    do {
        if (pila_top(tmp)) 
            coda_enqueue(tmp);
    } while (pila_pop());
    
    do {
        if (coda_first(tmp))
            pila_push(tmp);
    } while (coda_dequeue());
    coda_deinit();
}

signed main(int argc, char** argv) {
    checkArgs(2,argc);
    readIntToQueue(argv[1]);
    invertiPila();
    putQueueInFile(argv[2]);
    
}


void checkArgs(int req, int argc) {
    if (req != argc-1) {
        cout << "Error arguments, expected "<<req<<", got "<<argc-1<<endl;
        exit(1);
    }
}
