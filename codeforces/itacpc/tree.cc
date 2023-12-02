#include <bits/stdc++.h>
using namespace std;
// https://cp-algorithms.com/data_structures/disjoint_set_union.html
// https://usaco.guide/gold/dsu?lang=cpp
struct DSU {
	vector<int> e;
	DSU(int N) { e = vector<int>(N, -1); }

	// get representive component (uses path compression)
	int get(int x) { return e[x] < 0 ? x : e[x] = get(e[x]); }

	bool same_set(int a, int b) { return get(a) == get(b); }

	int size(int x) { return -e[get(x)]; }

	bool unite(int x, int y) {  // union by size
		x = get(x), y = get(y);
		if (x == y) return false;
		if (e[x] > e[y]) swap(x, y);
		e[x] += e[y];
		e[y] = x;
		return true;
	}
};

int main() {
    int N, M; cin >> N >> M;
    int add, remove; cin >> add >> remove;
    int from, to;
    int edgesToRemove = 0;
    int subgraphs = N;
    DSU subgraph(N+1);
    bool notSame;

    while(M--) {
        cin >> from >> to;

        //cout << subgraph.size(from) << " " << subgraph.size(to) << endl;
        notSame = subgraph.unite(from, to);
        if (notSame)
            subgraphs--;
        else
            edgesToRemove++;
        //cout << subgraphs << " " << edgesToRemove << endl;

    }
    int out = (subgraphs-1) * add + edgesToRemove * remove;
    cout << out << endl;

    return 0;
}