using namespace std;
#include <bits/stdc++.h>

int power(int base, int expo) {
    return expo ? base * power(base, expo-1) : 1;
}

int gcd(int a, int b) {
    if (!b) return a;
    return a%b ? gcd(b, a%b) : b;
}

void stampa(char a, char b) {
    cout << a << " ";
    if (a != b) stampa(a+1, b);
}

void printFactors(int n, int i=2) {
    if (i > sqrt(n)) {
        cout << n << " ";
        return;
    }

    if (n%i) {
        printFactors(n, i+1);
    } else {
        cout << i << " ";
        printFactors(n/i, 2);
    }
}

void printLine(int* v, int n) {
    for (int i=0;i<n;i++) cout << v[i];
    cout << endl;
}

void printTower(int** v, int n) {
    for (int i=0;i<3;i++) printLine(v[i], n);
    cout << endl;
}

int getTop(int* v, int n) {
    int i;
    for (i=n-1;i>=0 && v[i] == 0;i--);
    return i; // -1 if not found (should not happen)
}

void moveOne(int** v, int n, int source, int target) {
    int i_src = getTop(v[source], n);
    int i_trg = getTop(v[target], n);
    
    v[target][i_trg+1] = v[source][i_src];
    v[source][i_src] = 0;
} 

void hanoi(int** spares, int n, int target=2, int source=0, int spare=1, int m=-1) {
    if (m==-1) m=n; // strange default
    printTower(spares,n);

    if (m>1) {
        hanoi(spares,n, spare, source, target, m-1);
        moveOne(spares,n, source, target);
        hanoi(spares,n, target, spare, source, m-1);
    } else {
        moveOne(spares,n, source, target);
        printTower(spares,n);
    }
}

signed main() {
    int n = 9;
    int **tower = new int *[3];
    for (int i=0;i<3;i++) tower[i] = new int[n];
    
    for(int i=0;i<n;i++) tower[0][i] = n-i;
    hanoi(tower, n);
    return 0;
}
