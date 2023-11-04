#include <iostream>
#include <cstdlib>
#include <fstream>
#define RESET   "\033[0m"
#define RED     "\033[31m"
using namespace std;

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

void transposeSquare(int** matrix, int r, int c) {
    if (r!=c) exit(1);

    for (int i=0; i<r; i++) {
        for (int j=0; j<i; j++) {
            // lower triangular cicle
            //xor swap of symmetric
            matrix[i][j] ^= matrix[j][i];
            matrix[j][i] ^= matrix[i][j];
            matrix[i][j] ^= matrix[j][i];
        }
    }
}

int** getTransposed(int** matrix, int r, int c) {
    int **out = getMatrix(c, r);
    for (int i=0; i<r; i++) {
        for (int j=0; j<c; j++) 
            out[j][i] = matrix[i][j];
    }
    return out;
}

int superiorSum(int** matrix, int r, int c) {
    int sum = 0;
    for (int i=0; i<r; i++) {
        for (int j=i; j<c; j++) 
            sum += matrix[i][j];
    }
    return sum;
}

double filterCell(int** in, int r, int c, int y, int x, int filter[][2], int filterLen) {
    int sum = 0, valid = 0;
    for (int e=0;e<filterLen; e++) {
        if (filter[e][0] + y >=0 && 
            filter[e][1] + x >=0 &&
            filter[e][0] + y < r &&
            filter[e][1] + x <c) {
                sum += in[y + filter[e][0]][x + filter[e][1]];
                valid++;
            }
    }
    return (double)sum / valid;
}

void meanFilter(int** in, double** out, int r, int c) {
    const int filterLen = 4;
    int filter[filterLen][2] = {{1,0},{-1,0},{0,1},{0,-1}};
    for (int i=0; i<r; i++) {
        for (int j=0; j<c; j++) {
            out[i][j] = filterCell(in,r,c, i, j, filter, filterLen);
        }
    }
}

// encode the path in base 4 in an integer. (2 bit per cell)
// the max width of the table is 16 cell (for int as path)
// 0 means no possible path
// 1 up, 2 straight, 3 down
// easily convertible to rows (sum -2 and vice-versa)
unsigned long long findPath(int** m, int r, int c, int y, int x) {
    if (x+1 == c) return 2; //reached the end, go straight
    unsigned long long path;
    for (int dir=-1; dir < 2; dir++) {
        if (y+dir >= 0 && y+dir < r && m[y+dir][x+1]) {
            path = findPath(m,r,c, y+dir, x+1);
            if (path) {
                // path found
                return (path << 2) + dir + 2;
            }
        }
    }
    return 0; // no path
}

int* getPathRows(unsigned long long path, int columns, int startRow) {
    int *pathRows = new int[columns];
    int currentRow = startRow;
    for (int i=0; i<columns; i++) {
        pathRows[i] = currentRow;
        currentRow += (path & 3) -2;
        path >>= 2;
    }
    return pathRows;
}

void printPath(int** m, int r, int c, int* pathRows) {
    char tmp;
    for (int i=0; i<r; i++) {
        for (int j=0; j<c; j++) {
            tmp = m[i][j] ? '*' : '-';
            if (i == pathRows[j])
                cout << RED << tmp << RESET;
            else
                cout << tmp;
        }
        cout << endl;
    }
}

void sabbieMobili(int height, int width) {
    if (width > sizeof(unsigned long long)*4) {
        cout << RED << "Swamp width too bit, the maximum is " << RESET << sizeof(unsigned long long)*4 << endl;
        exit(1);
    }

    int **palude = getMatrix(height, width);
    fillRnd(palude, height, width, 2); // fill of 0 and 1

    unsigned long long path=0;
    int i;
    for (i=0; i<height && !path; i++) {
        if (palude[i][0])
            path = findPath(palude,height,width, i,0);
    }

    int *pathRows = new int[width];
    if (path) {
        pathRows = getPathRows(path, width, i-1);
    }else{
        cout << "No path available across the swamp :(" << endl;
        for(i=0;i<width;i++) pathRows[i]= -1;
    }
    printPath(palude,height,width,pathRows);
}

signed main(int argc, char **argv) {
    sabbieMobili(14,32);

}
