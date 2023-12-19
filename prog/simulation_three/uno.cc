#include<iostream>
#include<fstream>
#include<cstring>
#include<cmath>
using namespace std;

const int MAX_SEARCH_LEN = 255;

int strlen(char* str) {
    int i;
    for(i=0; str[i];i++);
    return i;
}

void rightShiftOne(char* str, int len) {
    int last = str[len-1];
    for(int i=len-1; i>0; i--)
        str[i] = str[i-1];
    str[0] = last;
}

void rightShiftStr(char* str, int dist) {
    int len = strlen(str);
    dist %= len;
    for(int i=0; i<dist; i++)
        rightShiftOne(str, len);
}

void capitalize(char* str) {
    for(int i=0; str[i]; i++) {
        if ('a' <= str[i] && str[i] <= 'z')
            str[i] -= ' '; // ascii assumed
    }
}

int countStrInFile(char* target, fstream &text) {
    int trgI = 0, out=0;
    char cur;
    while(text >> cur) {
        if (cur == target[trgI]) 
            trgI++;
        else
            trgI = 0;
            
        if (!target[trgI]) {
            // found a string
            out++;
            trgI = 0;
        }
    }
    return out;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    cerr << "Wrong argument number, a file path is expected" << endl;
    exit(1);
  }
  fstream in;
  in.open(argv[1], ios::in);
  if (in.fail()) {
    cerr << "Error opening the file!" << endl;
    exit(1);
  }
  char* search = new char[MAX_SEARCH_LEN+1];
  cout << "Word to search: ";
  cin >> search;
  int rot;
  cout << "Rot: ";
  cin >> rot;
  capitalize(search);
  rightShiftStr(search, rot);
  int out = countStrInFile(search, in);
  cout << "Word " << search << " found " << out << " times" << endl; 
  
  
  return 0;

}
