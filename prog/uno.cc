#include <iostream>
#include <fstream>

using namespace std;

void checkArgs(int, int);
void copyCorrrected(char*, char*);
void checkOpen(fstream&, char*);
bool isPunctuation(char);
bool isAlpha(char);

signed main(int argc, char** argv) {
    checkArgs(argc,2);
    copyCorrrected(argv[1], argv[2]);
    return 0;
}

void checkArgs(int argc, int wanted) {
    if (argc-1 != wanted) {
        cerr << "Wrong argument number!" << endl;
        exit(1);
    }
}

void checkOpen(fstream &file, char* name) {
    if (file.fail()) {
        cout << "Error opening file " << name << endl;
        exit(1);
    }
}

bool isPunctuation(char c) {
    switch (c)
    {
    case '.':
    case '!':
    case '?':
        return true;
    default:
        return false;
    }
}

bool isAlpha(char c) {
    return ('a' <= c && c <= 'z') ||
        ('A' <= c && c <= 'Z');
}

void copyCorrrected(char* src, char* dest) {
    char tmp;
    fstream in, out;
    in.open(src, ios::in);
    out.open(dest, ios::out);
    checkOpen(in, src);
    checkOpen(out, dest);

    bool isAfterPunctuation = true;

    while (!in.eof() && !in.fail()) {
        in.get(tmp);
        if (isPunctuation(tmp))
            isAfterPunctuation = true;
        else if (isAfterPunctuation && isAlpha(tmp)) {
            isAfterPunctuation = false;
            if (tmp > 'Z') // is lower
                tmp -= ' '; // to lower
        }
        out << tmp;
    }

    in.close();
    out.close();
}
