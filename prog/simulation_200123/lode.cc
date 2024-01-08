#include <iostream>
#include <cstdlib>
#include <ctime>

// NON MODIFICARE IL CODICE SOTTO FINO A "NON MODIFICARE IL CODICE SOPRA"
#define MAXVALUE 100
#define MAXSIZE 10

struct list {
  int info;
  list * next;
};

void delete_list(list * &l) {
  if (l != NULL) {
    delete_list(l->next);
    delete l;
    l = NULL;
  }
}

void print_list(const list * l) {
  if (l != NULL) {
    std::cout << " " << l->info;
    print_list(l->next);
  }
  else
    std::cout << std::endl;
}

list * create_list(int n) {
  if (n == 0) return nullptr;
  else return new list { rand()%MAXVALUE, create_list(n-1)};
}
// NON MODIFICARE IL CODICE SOPRA

// Inserire qui sotto la definizione della funzione f
bool f(list* element, int sum=0, bool first = true) {
    if (!element)
        // empty list
        return false;
    if (!element->next) {
        if (first)
            return true;
        return sum == element->info;
    }
    return f(element->next, sum+element->info, false);
}
// Inserire qui sopra la definizione della funzione f


int main(int argc, char ** argv) {
  // NON MODIFICARE IL MAIN
  srand(unsigned(time(0)));
		//
		// Commentare la linea seguente per avere comportamento
		// non-deterministico
		//
		srand(0);

  list * l[10];
  for (int i = 0; i < 7; i++) {
    l[i] = create_list(rand()%MAXSIZE);
  }
  l[7] = nullptr;
  l[7] = new list {34, l[7]};
  l[7] = new list {9, l[7]};
  l[7] = new list {8, l[7]};
  l[7] = new list {7, l[7]};
  l[7] = new list {6, l[7]};
  l[7] = new list {4, l[7]};
  l[8] = nullptr;
  l[8] = new list {34, l[8]};
  l[9] = nullptr;
  l[9] = new list {0, l[9]};

  for(int i = 0; i < 10; i++) {
    std::cout << "l[" << i << "] =";
    print_list(l[i]);
    std::cout << "f(l[" << i << "]) = " << f(l[i]) << std::endl;
    delete_list(l[i]);
  }
  // NON MODIFICARE IL MAIN
}
