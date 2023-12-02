#include <bits/stdc++.h>

using namespace std;

struct node {
    int sec;
    int people;
    node *l=NULL, *r=NULL;
};
typedef node* tree;

void insert(tree &t, int sec, int people) {
    if(t == NULL) {
        t = new node;
        t->sec = sec;
        t->people = people;
        return;
    }
    if(t->sec == sec) {
        t->people += people;
        return;
    }
    insert(sec > t->sec ? t->r : t->l, sec, people);
}

void getMaxPeople(tree t, int &max, int &curr) {
    if (!t) return;

    getMaxPeople(t->l, max, curr);
    curr += t->people;
    if (curr > max) max = curr;
    getMaxPeople(t->r, max, curr);
} 

int main() {
    int N; cin >> N;
    tree t = NULL;
    int p, sec;
    while(N--) {
        cin >> p >> sec;
        insert(t, sec, p);
    }
    int max = 0, curr = 0;
    getMaxPeople(t, max, curr);
    cout << max << endl;

    return 0;
}