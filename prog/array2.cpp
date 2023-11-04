using namespace std;
#include <iostream>
#include <ctime>
#include <cstdlib>

int convertToBase(int n, int base) {
    if (!n) return 0;
    int reminder = n % base;
    int out = convertToBase(n / base, base);
    return out * 10 + reminder;
}

int bit_len(int n) {
    int bits;
    for(bits=0; n!=0; bits++) n>>=1;
    return bits;
}

bool is_power_of_two(int n) {
    return n && !(n & (n - 1));
}

int pow(int base, int exp) {
    if (exp == 0) return 1;
    return base * pow(base, exp - 1);
}

int convertToBaseArr(int num, int base) {
    if (!is_power_of_two(base)) exit(1);
    int arr_len = bit_len(num)/bit_len(base-1)+1;
    int *resti = new int[arr_len];

    for (int i=0; num >0; i++) {
        resti[i] = num % base;
        num /= base;
    }

    int out = 0;
    for (int i = arr_len-1; i>= 0; i--) {
        // does not work for bases > 10
        out += resti[i] * pow(10, i);
    }
    return out;
}

int bubble(int arr[], int end, int start= 0, bool swapped= false) {
    if (start == end)
        // guard clauses :)
        return swapped ? bubble(arr, end - 1) + 1 : 1;
    
    if (arr[start] > arr[start + 1]) {
        // xor swap
        arr[start] ^= arr[start + 1];
        arr[start + 1] ^= arr[start];
        arr[start] ^= arr[start + 1];

        return bubble(arr, end, start + 1, true)+1;
    } else {
        return bubble(arr, end, start + 1, swapped)+1;
    }
}

void populateRnd(int arr[], int len, int max) {
    srand(time(NULL));
    for (int i = 0; i < len; i++) {
        arr[i] = rand() % max;
    }
}

void printArr(int arr[], int len) {
    for (int i = 0; i < len; i++) {
        cout << arr[i] << " ";
    }
    cout << endl;
}

int getPrev(int arr[], int i) {
    for (i--; i>=0 && arr[i] == -1; i--);
    return i;
}

void removeDoubles(int arr[], int len) {
    for (int i= 1; i < len-1; i++) {
        // should never be -1, the first is alwais kept
        if (arr[i] == arr[getPrev(arr, i)]) {
            arr[i] = -1;
        }
    }
}

void merge(int uno[], int lenUno, int due[], int lenDue, int out[]) {
    // lenOut is lenUno+lenDue
    int i=0, k=0;
    while (i < lenUno && k < lenDue) {
        if (k==lenDue || (i!=lenUno && uno[i] < due[k]))
            // the left part is evaluated after the right part(so I increment i there)
            out[(i++)+k] = uno[i];
        else
            out[i+(k++)] = due[k];
    }
}

int binarySearch(int arr[], int start, int end, int query) {
    int half = (start + end) / 2;
    if (arr[half] == query) 
        return half;
    if (start >= end) 
        return -1;

    if (arr[half] > query) 
        return binarySearch(arr, start, half -1, query);
    if (arr[half] < query) // just for clarity, it's always true
        return binarySearch(arr, half + 1, end, query);
    exit(1);//?
}

signed main() {
    const int len = 10;
    int arr[len];
    populateRnd(arr, len, 20);
    cout << "bubble: " << bubble(arr, len-1) << endl;
    printArr(arr, len);
    cout << "Index of 10: " << binarySearch(arr, 0, len-1, 10) << endl;

}