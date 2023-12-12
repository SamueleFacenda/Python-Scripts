#include <iostream>
#include "pila.h"


using namespace std;


/**
 * Ricordare che il file "pila.h" contiene la definizione della struct "cella" (qui sotto riportata)
 * 
 * struct cella {
 *   int indiceRiga;
 *   int indiceColonna;
 * };
 */
void risolviLabirinto(int [][5], int, int);
bool isValidCell(int, int);
void printResult(bool [5][5]);


int main(int argc, char* argv[]) {

    // Se modificate la funzione "main", ricordarsi poi di ripristinare il codice originale  

    // E' possibile modificare la matrice per effettuare dei test   
    int labirinto[5][5] = {
        { 1, 0, 1, 1, 0 },
        { 1, 1, 1, 0, 1 },
        { 0, 1, 0, 1, 1 },
        { 1, 1, 1, 1, 1 },
        { 1, 1, 1, 1, 1 }
    };

    // E' possibile modificare la cella di arrivo per effettuare dei test (la cella di partenza invece è sempre [0,0])   
    cout<<"Percorso: ";
    risolviLabirinto(labirinto, 4, 2);
   
    return 0;
}

bool isValidCell(int x, int y) {
    return x >= 0 && x < 5 && y >= 0 && y < 5;
}

void risolviLabirinto(int mappa[][5], int x, int y) {
    // x are rows? y are cols? yes but no
    init();
    push({0,0});
    int dirs[4][2] = {{0,1},{1,0},{-1,0},{0,-1}};
    bool visited[5][5] = {0}; // all false

    cella curr;
    int tmpX, tmpY;
    // finchè non becco la soluzione
    do {
        top(curr);
        pop();
        if (!visited[curr.indiceRiga][curr.indiceColonna]){
            // i copy again the cell in the stack to have a backtrace
            visited[curr.indiceRiga][curr.indiceColonna] = true;
            push(curr);
            // foreach dir
            for(int dir=0; dir<4; dir++) {
                tmpX = curr.indiceRiga + dirs[dir][0];
                tmpY = curr.indiceColonna + dirs[dir][1];
                if (isValidCell(tmpX, tmpY) && mappa[tmpX][tmpY] && !visited[tmpX][tmpY]) {
                    push({tmpX, tmpY}); 
                }
            }
        }
    } while(!vuota() && (curr.indiceRiga != x || curr.indiceColonna != y));

    if (curr.indiceRiga != x || curr.indiceColonna != y) 
        cout << "No available path!" << endl;
    else
        printResult(visited);
    deinit();
}

void printResult(bool visited[5][5]) {
    cout << "(inverso) ";
    cella curr;
    while(!vuota()){
        top(curr);
        pop();
        if(visited[curr.indiceRiga][curr.indiceColonna]) {
            cout << "[" << curr.indiceRiga << ", " << curr.indiceColonna << "]";
            if(!vuota())
                cout << ", ";
        }
    }
    cout << endl;

}