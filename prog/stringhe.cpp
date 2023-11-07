#include <iostream>
#include <cstdlib>
#include <fstream>

using namespace std;

int getScore(char*);

bool isAlpha(char*);

bool isAlpha(char);

void swapCase(char*);

int sumAdiacent(char*);

int abss(int);

int calc(char*, char*, char);

void printFileContent(char*);

void checkArgs(int, int);

void copyFile(char*, char*);

void censore(char*, char);

bool equals(char*, char*);

void copyIntersection(char*, char*, char*);

void addFileToWordList(fstream&, char** list, int&);

void addFileAndItersectList(fstream&, char**, int, char**, int&);

bool listContains(char** list, int wc, char* word);

signed main(int argc, char** argv) {
    checkArgs(argc, 3);
    copyIntersection(argv[1], argv[2], argv[3]);
}

int getScore(char* str) {
    if(!isAlpha(str)) return -1;

    swapCase(str);
    cout << str << endl;
    return sumAdiacent(str);
}

bool isAlpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool isAlpha(char* str) {
    int i;
    // iterate the string while is alpha
    for (i=0; str[i] && isAlpha(str[i]); i++);
    return !str[i]; // the iteration finished with all alpha
}

void swapCase(char* str) {
    // the string must be all alphabetic
    for (int i=0; str[i]; i++) {
        str[i] += (str[i]<='Z') ? ' ' : -' ';
    }
}

int sumAdiacent(char* str) {
    int sum = 0;
    for(int i=0; str[i] && str[i+1]; i++) {
        sum += abss(str[i+1] - str[i]);
    }
    return sum;
}

int abss(int n) {
    return (n<0) ? -n : n;
}

int calc(char* uno, char* due, char op) {
    int a = atoi(uno);
    int b = atoi(due);
    switch (op) {
        case '+':
            return a + b;
        case '-':
            return a - b;
        case '*':
            return a * b;
        case '/':
            return a / b;
        default:
            exit(1);
    }
}

void printFileContent(char* fileName) {
    fstream fd;
    fd.open(fileName, ios::in);
    if (fd.fail()) exit(1);
    char tmp;
    while(!fd.eof()) {
        fd.get(tmp);
        cout << tmp;
    }
    fd.close();
}

void checkArgs(int argc, int req) {
    if (argc-1 != req) {
        cout << "Incorrect argument number! " << (argc-1) << " provided, " << req << " required" << endl;
        exit(1);
    }
}

void copyFile(char* src, char* dst) {
    fstream in, out;
    in.open(src, ios::in);
    out.open(dst, ios::out);

    if (in.fail()) {
        cout << "Errors opening source file..." << endl;
        exit(1);
    }
    if (out.fail()) {
        cout << "Errors opening destination file..." << endl;
        exit(1);
    }

    out << in.rdbuf();

    out.close();
    in.close();
}

void censore(char* str, char c) {
    for(int i=0; str[i]; i++) {
        if(str[i] == c)
            str[i] = '?';
    }
}

bool equals(char* a, char* b) {
    int i;
    for(i=0; a[i] && b[i] && a[i]==b[i]; i++);
    return !a[i] && !b[i];
}

void copyIntersection(char* uno, char* due, char* dest) {
    fstream a, b, dst;
    a.open(uno, ios::in);
    b.open(due, ios::in);
    dst.open(dest, ios::out);
    if (a.fail() || b.fail() || dst.fail()) exit(1);

    char** words = new char*[1000];
    int wc = 0;

    char** intersection = new char*[1000];
    int wcIntersect = 0;
    
    addFileToWordList(a, words, wc);
    addFileAndItersectList(b , words, wc, intersection, wcIntersect);

    for (int i=0; i<wcIntersect; i++) {
        dst << intersection[i] << endl;
        delete[] intersection[i]; // free the space
    }

    for (int i=0; i<wc; i++) delete[] words[i];

    delete[] words;
    delete[] intersection;
    a.close();
    b.close();
    dst.close();
}


void addFileToWordList(fstream &src, char** list, int &wc) {
    char* tmp = new char[100];

    while(!src.eof()) {
        src >> tmp;
        if (!listContains(list, wc, tmp)) {
            list[wc] = tmp;
            wc++;
            tmp = new char[100];
        }
    }
}

void addFileAndItersectList(fstream &src, char** words, int wc, char** out, int &wcOut) {
    char* tmp = new char[100];

    while(!src.eof()) {
        src >> tmp;
        if (listContains(words, wc, tmp)) {
            out[wcOut] = tmp;
            wcOut++;
            tmp = new char[100];
        }
    }
}

bool listContains(char** list, int wc, char* word) {
    int i;
    for(i=0; i<wc && !equals(word, list[i]); i++);
    return i<wc;
}
