#include <iostream>
#include <cstdlib>
#include <fstream>

using namespace std;

#define RESET   "\033[0m"
#define RED     "\033[31m"

int** getMatrix(int rows, int cols) {
    int **matrix = new int*[rows];
    for (int i = 0; i < rows; i++) {
        matrix[i] = new int[cols];
    }
    return matrix;
}

double** getDoubleMatrix(int rows, int cols) {
    double **matrix = new double*[rows];
    for (int i = 0; i < rows; i++) {
        matrix[i] = new double[cols];
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

void printMatrix(double** matrix, int r, int c) {
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

void fillRnd(double** matrix, int r, int c, int max) {
    srand(time(NULL));
    for (int i=0; i<r; i++) {
        for (int j=0; j<c; j++) 
            matrix[i][j] = rand() % max;
    }
}


void S(double** m, int a, int b) {
    double *tmp = m[a];
    m[a] = m[b];
    m[b] = tmp;
}

void D(double** m, int len, int row, double val) {
    for(int i=0;i<len; i++) {
        m[row][i] *= val;
    }
}

void E(double** m, int len, int a, int b, double val) {
    for(int i=0;i<len; i++) {
        m[a][i] += m[b][i] * val;
    }
}

void stairReduction(double** m, int r, int c) {
    int nonZeroRow;
    int currentPivot = 0;
    for(int col=0;col<c; col++) {
        // require the first row cell at 0
        for(nonZeroRow = currentPivot; nonZeroRow<r && !m[nonZeroRow][col]; nonZeroRow++);

        if (nonZeroRow != r) {
            // there is a cell that is not zero
            S(m,currentPivot, nonZeroRow);
            // reduce all the other rows
            for(int row=currentPivot+1; row<r; row++) {
                E(m,c, row, currentPivot, -m[row][col]/m[currentPivot][col]);
            }
            currentPivot++;
        }
    }
}

int pivotIndex(double** m, int columns, int row) {
    int i;
    for(i=0; i<columns && !m[row][i]; i++);
    return i==columns ? -1 : i;
}

void reduceStair(double** m, int r, int c) {
    int pivot;
    for (int row =r-1; row >=0; row--) {
        pivot = pivotIndex(m,c, row);
        if (pivot != -1) {
            // make the pivot=1
            D(m,c, row, 1/m[row][pivot]);
            // delete all values in column using the pivot
            for(int upperRow = row-1; upperRow >=0; upperRow--) {
                // the pivot is 1, I have to multiply for negative the value that I want to delete
                E(m,c, upperRow, row, -m[upperRow][pivot]);
            }
        }
    }
}

int rg(double** m, int r, int c) {
    int i;
    for (i=r-1; r>=0 && pivotIndex(m,c,i) == -1; i++);
    return i+1;
}

signed main(int argc, char **argv) {
    int r=5,c=6;
    double **m = getDoubleMatrix(r,c);
    fillRnd(m,r,c,3);
    printMatrix(m,r,c);
    stairReduction(m,r,c);
    cout << endl;
    printMatrix(m,r,c);
    reduceStair(m,r,c);
    cout << endl;
    printMatrix(m,r,c);
}
