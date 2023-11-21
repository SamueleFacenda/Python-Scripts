#include "utils.hpp"
#include <iostream>
using namespace std;

void crypt(char* word, int key) {
    for(int i=0; word[i]; i++) {
        if ('a' <= word[i] && word[i] <= 'z')
            word[i] = (word[i] -'a' +key)%('z'-'a') + 'a';
    }
}

void decrypt(char* word, int key) {
    for(int i=0; word[i]; i++) {
        if ('a' <= word[i] && word[i] <= 'z')
            word[i] = (word[i] -'a' + ('z'-'a') -key)% ('z'-'a') + 'a';
    }
}
