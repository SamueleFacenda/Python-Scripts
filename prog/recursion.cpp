using namespace std;
#include <bits/stdc++.h>

int fact(int n)  {
    return (n<=1? 1 : n*fact(n-1) );
}

int div(int a, int b, int& resto) {
    if (b > a) {
        resto = a;
        return 0;
    } else {
        return 1 + div(a-b, b, resto);
    }
}

void bin(int n) {
    if (n > 1) bin(n/2);
    cout << n%2;
}

int getLast(int n) {
    return n%10;
}

int getFirst(int n) {
    return n < 10 ? n : getFirst(n/10);
}

int removeFirst(int n) {
    return n%(int)pow(10,(int)log10(n));
}

int removeSides(int n) {
    return removeFirst(n)/10;
}

bool palindromo(int n) {
    if (n < 10) {
        return true;
    }
    
    return (getFirst(n) == getLast(n)) && palindromo(removeSides(n));    
}

int sommaCifre(int n) {
    return n<10 ? n : n%10+sommaCifre(n/10);
}

int main() {
    cout << sommaCifre(12345) << endl;
}
