#include<iostream>
#include<fstream>
#include<cstring>
#include<cmath>
using namespace std;


int decode(char * word) {
    int i, out=0;
    for(i=0; word[i]; i++); // goto end word
    i--;
    for(int pow=1;i>=0; i--, pow*=36) {
        out += (word[i]>='a' ?
            word[i]-'a'+10:
            word[i]-'0') * pow;
    }
    return out;
}

void encode(int coded, char str[]) {
    int len;
    int arr[6];
    for(len=0; coded>0; len++, coded/=36) {
        arr[len] = coded%36;
    }
    str[len] = '\0';
    len--;
    for(int i=0; i<=len; i++) {
        str[i] = arr[len-i] < 10 ?
            arr[len-i] + '0':
            arr[len-i] + 'a' - 10;
    }
}



int main(int argc, char * argv []) {
  
  if (argc != 3) {
    cerr << "Non ci sono due file in input!" << endl;
    exit(1);
  }
  
  int key;
  do {
    cout << "Inserire chiave di crittazione! (max 7 cifre)" << endl;
    cin >> key;
  } while(key >= 1e7 );
  
  fstream in, out;
  
  in.open(argv[1], ios::in);
  if (in.fail()) {
    cerr << "Failed opening input file!" << endl;
    exit(1);
  }
  
  out.open(argv[2], ios::out);
  if (out.fail()) {
    cerr << "Failed opening output file!" << endl;
    in.close();
    exit(1);
  }
  
  char buff[50];
  int val;
  while(in >> buff) {
    buff[4] = '\0';
    val = decode(buff) + key;
    encode(val, buff);
    out << buff << " ";
  }
  out << endl;
  
  in.close();
  out.close();
    
  return 0;

}
