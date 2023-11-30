#include <iostream>
#include <cstdlib>
#include <fstream>

using namespace std;

// # define int unsigned long long

struct node {
    int val;
    node* l=nullptr;
    node* r=nullptr;
};
typedef node* tree;

void addValToTree(tree &root, int val) {
    if (root) {
        addValToTree(root->val < val ? root->r : root->l ,val);
    } else {
        root = new node;
        root->val = val;
    }
}

void printOrdered(tree root) {
    if (root) {
        printOrdered(root->l);
        cout << root->val << " ";
        printOrdered(root->r);
    }
}

int* getPath(tree root, int val, int depth=0) {
    if (!root)
        return nullptr;
    int *out;
    if (root->val == val) {
        out = new int[depth+1];
    } else {
        out = getPath(val > root->val ? root->r : root->l, val, depth+1);
    }
    if (out)
        //nullptr means not found
        out[depth] = root->val;
    return out;
}

void printPath(tree root, int val) {
    int *path = getPath(root, val);
    if (path) {
        for(int i=0; i==0 || path[i-1]!=val; i++) 
            cout << path[i] <<" ";
        cout << endl;
    } else {
        cout << "Not found!" << endl;
    }
}


signed main(int argc, char** argv) {
    fstream in;
    in.open(argv[1], ios::in);

    tree root=nullptr;
    int tmp;
    while(in >> tmp) {
        addValToTree(root, tmp);
    }
    //printOrdered(root);
    
    printPath(root, 4);
    
    
    
    return 0;
}
