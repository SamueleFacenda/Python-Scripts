#include "utils.hpp"
#include <iostream>
#include <fstream>
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

void extend(char* &arr, int &len) {
    char *out = new char[len*2];
    for(int i=0; i<len; i++)
        out[i] = arr[i];
        
    len *= 2;
    delete[] arr;
    arr = out;
}

void extend(int* &arr, int &len) {
    int *out = new int[len*2];
    for(int i=0; i<len; i++)
        out[i] = arr[i];
        
    len *= 2;
    delete[] arr;
    arr = out;
}


char* readFile(char* name) {
    fstream in;
    in.open(name, ios::in);

    int size = 50;
    char* out = new char[size];
    for(int i=0;!in.eof(); i++){
        if(i+1==size) 
            extend(out, size);
    
        in.get(out[i]);
        out[i+1]='\0';
    }
    return out;
}

char* getUpper(char* str, int i, int found) {
    char* out;
    if(!str[i]) {
        out = new char[found+1];
        out[found] = '\0';
    } else {
        if ('A' <= str[i] && str[i] <= 'Z') {
            out = getUpper(str,i+1,found+1);
            out[found] = str[i];
        } else
            out = getUpper(str,i+1,found);
    }
    return out;
}

bool isEmail(char* email) {
    int atPos=-1;
    int i;
    for(i=0; email[i]; i++) {
        if (email[i]=='@') {
            if (atPos >0) {
                cerr << "Two @ found, error" << endl;
                return false;
            }
            atPos = i;
        }
    }
    
    if (email[0] == '.' 
        || email[i-1] == '.'
        //|| email[atPos-1] == '.'
        //|| email[atPos+1] == '.'
        ) {
        
        cerr << "Dots in invalid position found!" << endl;
        return false;
    }
    
    for(i=0; email[i]; i++) {
        if (!(
            ('A' <= email[i] && email[i] <= 'Z') ||
            ('a' <= email[i] && email[i] <= 'z') ||
            ('0' <= email[i] && email[i] <= '9') ||
            email[i] == '.' || 
            email[i] == '_' || 
            email[i] == '@'
            )) {
            
            cerr << "Carattere invalido trovaro!" << endl;
            return false;
        }
    }
    return true;
}
