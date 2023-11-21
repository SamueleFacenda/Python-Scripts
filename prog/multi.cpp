#include <iostream>
#include <cstdlib>
#include "utils.hpp"
#include <fstream>

using namespace std;

// # define int unsigned long long

signed main(int argc, char** argv) {
    fstream in;
    in.open("a.txt", ios::in);

    char* enc = new char[50];
    char tmp;
    for(int i=0; i<49 && !in.eof(); i++){
        in.get(enc[i]);
        enc[i+1]='\0';
    }
    
    crypt(enc,4);
    
    cout << enc << endl;
    decrypt(enc,4);
    cout << enc << endl;
    
    return 0;
}
