#include <iostream>
#include <cstdlib>

using namespace std;

// # define int unsigned long long

void inplaceMergeSort(int* arr, int len) {
    if (len==1) return;
    
    int half = len/2;
    inplaceMergeSort(arr,half);
    inplaceMergeSort(arr+half,len-half);
    
    // inplace merge
    for(int i=0; i<len; i++) {
        
    }
    # 0 1 2 4 6 
    # 3 4 5 6 
}

signed main(int argc, char** argv) {
    
    cout << "Hello world!" << endl;
    
    return 0;
}
