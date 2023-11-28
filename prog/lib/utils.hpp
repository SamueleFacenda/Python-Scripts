#ifndef UTILS_HPP
#define UTILS_HPP

void crypt(char* word, int key);
void decrypt(char* word, int key);
char* readFile(char* name);
void extend(char* &arr, int& len);
void extend(int* &arr, int &len);
char* getUpper(char* str, int i=0,int found=0);
bool isEmail(char* mail);

#endif
