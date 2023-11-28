#include <iostream>
#include <cstdlib>
#include <fstream>
#include "pila.h"
#include "utils.hpp"
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
}

signed main(int argc, char** argv) {
    checkArgs(2,argc);
    readIntToQueue(argv[1]);
    putQueueInFile(argv[2]);


    return 0;
}


void checkArgs(int req, int argc) {
    if (req != argc-1) {
        cout << "Error arguments, expected "<<req<<", got "<<argc-1<<endl;
        exit(1);
    }
}
