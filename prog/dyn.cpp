#include <iostream>
#include <cstdlib>
#include <fstream>

#define RESET   "\033[0m"
#define RED     "\033[31m"

using namespace std;

int* getRndArr(int len) {
    int *out = new int[len];
    srand(time(NULL));
    for(int i=0; i<len; i++)
        out[i] = rand() % 100;
    return out;
}

int** getMatrix(int rows, int cols) {
    int **matrix = new int*[rows];
    for (int i = 0; i < rows; i++) {
        matrix[i] = new int[cols];
    }
    return matrix;
}

void printMatrix(int** matrix, int r, int c) {
    for (int i=0; i<r; i++) {
        for (int j=0; j<c; j++) 
            cout << matrix[i][j] << "\t";
        cout << endl;
    }
}


void fillRnd(int** matrix, int r, int c, int max) {
    srand(time(NULL));
        for (int i=0; i<r; i++) {
        for (int j=0; j<c; j++) 
            matrix[i][j] = rand() % max;
    }
}

int** genMatrix(int r, int c) {
    int **out = getMatrix(r,c);
    fillRnd(out, r, c, 100);
    return out;
}

void delMatrix(int** m, int len) {
    for(int i=0; i<len; i++)
        delete[] m[i];
    delete[] m;
}

void expand(double* &arr, int &len) {
    len *= 2;
    double *out = new double[len];
    for(int i=0; i<len; i++) 
        out[i] = arr[i];
    delete[] arr;
    arr = out;
}

double* readTemperatures(char* file, int &read) {
    read = -1;
    int len = 10;
    double *out = new double[len];
    fstream in;
    in.open(file, ios::in);
    if(in.fail()) {
        cerr << "File not found or busy..." << endl;
        exit(1);
    }
  
    while(!in.fail() && !in.eof()) {
        read++;    

        if (read == len)
            expand(out, len);
            
        in >> out[read];
    }
    
    return out;
}

int* concat(int* a, int lenA, int* b, int lenB) {
    int *out = new int[lenA + lenB];
    
    int i=0, j=0;
    while(i<lenA || j<lenB) {
        if(j==lenB || (i!=lenA && a[i] < b[j]))
            out[(i++)+j] = a[i];
        else
            out[i+(j++)] = b[j];
    }
    return out;
}


signed main(int argc, char **argv) {
    int *a=new int[] {1,2,3,4,5,6,7};
    int *b=new int[] {3,4,5,6,7,8,9,10};
    int *conc = concat(a, 7, b, 8);
    for(int i=0; i<15; i++) {
        cout << conc[i] << endl;
    }
}
