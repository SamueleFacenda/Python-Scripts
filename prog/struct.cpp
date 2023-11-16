#include <iostream>
#include <cstdlib>
#include <fstream>

using namespace std;

// # define int unsigned long long

#define NAME_LENGHT 30

struct Studente {
    char name[NAME_LENGHT], surname[NAME_LENGHT];
    int matricola;
    float media;
};

void stampaStudente(Studente* s) {
    cout << "Studente " << s->name << " "<<  s->surname << endl;
    cout << "Matricola: " << s->matricola << ", media: " << s->media << endl;
}

Studente* mkStudente(char name[NAME_LENGHT], char surname[NAME_LENGHT], int matricola, float media) {
    Studente *out = new Studente;
    for (int i=0; i<NAME_LENGHT; i++) {
        out->name[i] = name[i];
        out->surname[i] = surname[i];
    }
    out->matricola = matricola;
    out->media = media;
    return out;
}

void extend(void*** arr, int &len) {
    // pointer to an array of poiters
    void **out = new void*[len*2];
    for(int i=0; i<len; i++)
        out[i] = (*arr)[i];
        
    len *= 2;
    delete[] *arr;
    *arr = out;
}

Studente** fetchDB(char* file, int &count) {
    fstream dbFile;
    dbFile.open(file, ios::in);
    if (dbFile.fail()) exit(1);
    char name[NAME_LENGHT], surname[NAME_LENGHT];
    int matr;
    float media;
    
    int len = 10;
    count = 0;
    Studente **out = new Studente*[len];
    while(!dbFile.fail() && !dbFile.eof()) {

        if (count == len) {
            extend((void***) &out, len);
        }
    
        dbFile >> name >> surname >> matr >> media;
        if (!dbFile.fail()) { 
            out[count] = mkStudente(name, surname, matr, media);
            count++;
        }

    }
    return out;
}

int cercaMatricola(Studente **db, int len, int matricola) {
    int i=0;
    for(i=0; i<len && db[i]->matricola != matricola; i++);
    return i==len ? -1 : i;
}

int strcmp(char a[], char b[]) {
    int i;
    for(i=0; a[i] && b[i] && a[i]==b[i]; i++);
    return a[i] - b[i];
}

int cercaNomeCognome(Studente** db, int len, char name[], char surname[]) {
    int i=0;
    for(i=0; i<len && strcmp(name, db[i]->name) && strcmp(surname, db[i]->surname); i++);
    return i==len ? -1 : i;
}

int studenteTopMedia(Studente** db, int len) {
    if(!len) return -1;
    int top = 0;
    for(int i=1; i<len; i++) {
        if(db[i]->media > db[top]->media) 
            top = i;
    }
    return top;
}

int getChoice() {
    cout << " _ __ ___   ___ _ __  _   _ \n"
            "| '_ ` _ \\ / _ \\ '_ \\| | | |\n"
            "| | | | | |  __/ | | | |_| |\n"
            "|_| |_| |_|\\___|_| |_|\\__,_|\n" << endl;
    
    cout << "1: Aggiungi uno studente" << endl;
    cout << "2: Cerca per matricola" << endl;
    cout << "3: Cerca per nome e cognome" << endl;
    cout << "4: Cerca la media più alta" << endl;
    cout << "5: Carica studenti da file" << endl;
    cout << "6: Stampa gli studenti" << endl;
    cout << "0: esci" << endl; 
    
    int tmp;
    cin >> tmp;
    return tmp; 
} 

void insertStudent(Studente** &db, int &len, int &count) {
    char name[NAME_LENGHT], surname[NAME_LENGHT];
    int matr;
    float media;
    cout << "Inserisci il tuo studente (nome cognome matrice media)" << endl;
    cin >> name >> surname >> matr >> media;
    
    if (len==count)
        extend((void***) db, len);
    
    db[count] = mkStudente(name, surname, matr, media);
    count++;
}

void wrapCercaMatricola(Studente** db, int count) {
    cout << "Inserire la matricola da cercare: " << endl;
    int tmp;
    cin >> tmp;
    tmp = cercaMatricola(db,count, tmp);
    if (tmp >= 0)
        stampaStudente(db[tmp]);
    else
        cout << "Impossibile trovare la matricola :(" << endl;
}

void wrapCercaNomeCognome(Studente** db, int count) {
    cout << "Inserire nome e cognome: " << endl;
    char nome[NAME_LENGHT], cognome[NAME_LENGHT];
    cin >> nome >> cognome;
    int tmp = cercaNomeCognome(db,count, nome, cognome);
    if (tmp >= 0)
        stampaStudente(db[tmp]);
    else
        cout << "Impossibile trovare lo studente :(" << endl;
}

void wrapCercaMedia(Studente** db, int count) {
    int tmp = studenteTopMedia(db, count);
    if (tmp > 0)
        stampaStudente(db[tmp]);
    else
        cout << "Non ci sono studenti nel db :(" << endl;
}

void wrapCaricaStudenti(Studente** &db, int &len, int &count) {
    cout << "Inserire il nome del file: " << endl;
    char tmp[50];
    cin >> tmp;
    
    int newCount;
    Studente **newDb = fetchDB(tmp, newCount);
    for(int i=0; i<newCount; i++) {
        if (len==count) 
            extend((void***) &db, len);
    
        db[count] = newDb[i];
        count++;
    }
    delete[] newDb;
}

void stampaStudenti(Studente** db, int count) {
    for(int i=0; i<count; i++)
        stampaStudente(db[i]);
}

void menu(Studente** &db, int &len, int &count, int choice) {
    switch(choice) {
        case 0:
            exit(0);
        case 1:
            insertStudent(db,len,count);
            break;
        case 2:
            wrapCercaMatricola(db, count);
            break;
        case 3:
            wrapCercaNomeCognome(db, count);
            break;
        case 4:
            wrapCercaMedia(db, count);
            break;
        case 5:
            wrapCaricaStudenti(db, len, count);
            break;
        case 6:
            stampaStudenti(db, count);
            break;

    }

}

signed main(int argc, char** argv) {
    int count=0, len=10;
    Studente** db = new Studente*[len];
    int choice;
    while(choice = getChoice())
        menu(db, len, count, choice);

    for(int i=0; i<count; i++)
        delete db[i];
    delete[] db;
}
