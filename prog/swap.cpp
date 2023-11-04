using namespace std;
#include <iostream>
#include <climits>
#include<cstdlib>
#include<ctime>
// #define int long long int

void swap(int& a, int& b){
    a ^= b;
    b ^= a;
    a ^= b;
}

void swapV2(int& a, int& b){
    a ^= b & 255;
    b ^= a & 255;
    a ^= b & 255;
}

void swap(double& a, double& b){
    a += b;
    b = a - b;
    a -= b;
}

int divide(int a, int b, int& resto){
    resto = a % b;
    a -= resto;
    if (!a) return 0;
    
    int i;
    for (i=0;(1<<i)*b < a; i++); // exponential search for range
    
    // binary search for the result
    int top= 1<<i, bottom=1<<(i-1), tmp;
    do {
        tmp = (top + bottom)>>1;
        if (tmp*b < a) {
            bottom = tmp+1;
        } else if (tmp*b > a) {
            top = tmp-1;
        }
        cout << top << " " << bottom << endl;
    } while (tmp*b != a);
    return tmp;
}

void normalize(int* h, int* m, int* s){
    int carry = (*s) / 60;
    *s %= 60;
    *m += carry;
    
    carry = (*m) / 60;
    *m %= 60;
    *h += carry;
}

int max(int a, int b=INT_MIN, int c=INT_MIN, int d=INT_MIN, int e=INT_MIN) {
    int max = a;
    if (b > max) max = b;
    if (c > max) max = c;
    if (d > max) max = d;
    if (e > max) max = e;
    return max;
}

void sort(int& a, int& b, int& c){
    if (a > b) swap(a,b);
    if (a > c) swap(a,c);
    if (b > c) swap(b,c);
}

void initRnd(){
    srand(time(NULL));
}

int throwDice(){
    return rand()%6 +1;
}

void risiko(){
    int a1,a2,a3,d1,d2,d3;
    initRnd();
    a1= throwDice();
    a2= throwDice();
    a3= throwDice();
    d1= throwDice();
    d2= throwDice();
    d3= throwDice();
    sort(a1,a2,a3);
    sort(d1,d2,d3);
    
    int a=0,d=0;
    if (a3 > d3) a++; else d++;
    if (a2 > d2) a++; else d++;
    if (a1 > d1) a++; else d++;
    
    cout << "Punti attacco: " << a << endl;
    cout << "Punti difesa : " << d << endl;
    cout << "Vince " << (a > d ? "l'attacco" : "la difesa") << endl; 
}

signed main() {
    risiko();
    return 0;
}
