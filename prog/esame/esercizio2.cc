#include <iostream>
#include <cstdlib>

#define MAX_DIM 75

void fill_random_array(char * A, int N) {
  if (NULL != A) {
    for(int i = 0; i < N; i++) {
      A[i] = 'A' + rand()%(('A' - 'Z')+1);
    }
  }
}

void print_array(const char msg[], char * A, int N) {
  std::cout << msg;
  if (NULL != A) {
    for (int i = 0; i < N; i++) {
      std::cout << A[i];
    }
  }
  std::cout << std::endl;
}

/* Inserire qui sotto la dichiarazione della funzione conta */
void conta(char*, int, int, int, int*&);
int* contaWrapped(char*, int, int, int);
/* Inserire qui sopra la dichiarazione della funzione conta */

int main(int argc, char **argv) {
  unsigned int seed = (unsigned int)time(NULL);
  // seed = 60000
  seed = 1697033220;
  if (argc > 1) {
    seed = atoi(argv[1]);
  }
  std::cout << "Seed = " << seed << std::endl;
  srand(seed);

  char A[MAX_DIM];

  fill_random_array(A, MAX_DIM);
  print_array("A[] = ", A, MAX_DIM);
  int i, j;
  i = 0; j = -1;
  while(i > j) {
    i = rand()%MAX_DIM;
    j = rand()%MAX_DIM;
  }
  int * res;
  conta(A, MAX_DIM, i, j, res);
  std::cout << "i = " << i << ", j = " << j << std::endl;
  std::cout << "A[" << i << "] = " << A[i];
  std::cout << "  A[" << j << "] = " << A[j] << std::endl;
  std::cout << "There are " << res[0] << " occurrences of " << A[j];
  std::cout << " between indexes " << i << " and " << j
            << " (with A[" << i << "] included and A[" << j << "] excluded)" << std::endl;
  if (res[0] > 0) {
    std::cout << "They are at indexes: ";
    for(int l = 1; l < res[0]+1; l++) {
      std::cout << res[l] << " ";
    }
    std::cout << std::endl;
  }
  delete [] res;
}

/* Inserire qui sotto la definizione della funzione conta */
void conta(char* arr, int len, int i, int j, int* &res) {
    res = contaWrapped(arr, i, j, 1);
}

int* contaWrapped(char* arr, int i, int j, int foundIndex) {
    int *res;
    if (i == j) {
        res = new int[foundIndex];
        res[0] = foundIndex-1;
    } else if (arr[i] != arr[j]) {
        res = contaWrapped(arr, i+1, j, foundIndex+1);
        res[foundIndex] = i;
    } else {
        res = contaWrapped(arr, i+1, j, foundIndex);
    }
    return res;
}
/* Inserire qui sotto la definizione della funzione conta */
