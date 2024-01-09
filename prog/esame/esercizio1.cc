#include<iostream>
#include<fstream>
using namespace std;

const int LINE_MAX_LEN = 127 + 1;
const int NUM_ADDENDI = 13;
const int MAX_NUM_BITLEN = 8;

void elaborariga(char str[], int out[], int &ris);
int converti(int bin[], int len);
int somma(int nums[]);

int main(int argc, char * argv []) {

  fstream in, out;
  
  in.open("inputdati.txt", ios::in);
  if (in.fail()) {
    cerr << "Failed opening input file!" << endl;
    exit(1);
  }
  
  out.open("outputcheck.txt", ios::out);
  if (out.fail()) {
    cerr << "Failed opening output file!" << endl;
    in.close();
    exit(1);
  }

  char buff[LINE_MAX_LEN];
  int nums[NUM_ADDENDI];
  int ris;
  while (in >> buff) {
    elaborariga(buff, nums, ris);
    if (ris == somma(nums))
        out << ris << endl;
    else
        out << "Errore" << endl;
  }

  in.close();
  out.close();
    
  return 0;

}


void elaborariga(char str[], int out[13], int &ris) {
    int bin[MAX_NUM_BITLEN];
    int outIndex = 0, numLen=0;
    for(int i=0; str[i] != ';'; i++) {
        if (str[i] == '+' || str[i] == '=') {
            out[outIndex] = converti(bin, numLen);
            outIndex++;
            numLen=0;
        } else {
            bin[numLen] = str[i] - '0';
            numLen++;
        }
    }
    ris = converti(bin, numLen);

    // fill with 0 the remaining cells
    for(int i=outIndex; i<NUM_ADDENDI; i++)
        out[i] = 0;
}

int converti(int bin[], int len) {
    int out=0;
    for(int i=0; i<len; i++) {
        out += bin[len-i-1] * (1<<i);
    }
    return out;
}

int somma(int nums[]) {
    int out=0;
    for(int i=0; i<NUM_ADDENDI; i++)
        out += nums[i];
    return out;
}