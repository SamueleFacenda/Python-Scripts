using namespace std;
#include <iostream>
#include <cstdlib>
#include <ctime>

void initRnd() {
    srand(time(NULL));
}

int getRnd(int max) {
    return rand() % (max+1);
}

void stampa() {
    const int len = 10;
    initRnd();
    int arr[len];
    for (int i=0;i<len;i++) 
        arr[i] = getRnd(9);
        
    for (int i=0;i<len;i++)
        cout << arr[i] << ", ";
    cout << endl;
}

int uguaglianza(int n) {
    const int len = 10;
    int uno[len], due[len];
    initRnd();
    for (int i=0;i<len;i++) {
        uno[i] = getRnd(n); 
        cout << uno[i] << " ";
    }
    cout << endl;
    for (int i=0;i<len;i++) {
        due[i] = getRnd(n);
        cout << due[i] << " ";
    }
    cout << endl;
    
    int eq = 0;
    for (int i=0;i<len;i++) 
        eq += uno[i] == due[i];
    return eq;   
}

void invert(int arr[], int len) {
    for (int i=0;i<len/2;i++) {
        arr[i] ^= arr[len-i-1];
        arr[len-i-1] ^= arr[i];
        arr[i] ^= arr[len-i-1];
    }
}

signed main() {
    const int len = 11;
    int arr[len];
    for (int i=0;i<len;i++) arr[i] = i+1;

    invert(arr, len);
    for (int i=0;i<len;i++) cout << arr[i] << " ";
    cout << endl;
}
