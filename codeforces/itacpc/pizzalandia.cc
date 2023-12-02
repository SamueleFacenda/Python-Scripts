#include <bits/stdc++.h>

using namespace std;

int X, Y;

int lap() {
    return 2 * (X + Y);
}

struct pt {
    int x, y;
};

// convert x y to a line(start at top left)
int getCell(int x, int y) {
    if (y == 0) return x;
    if (x == X-1) return X-1 + y;
    if (y == Y-1) return X-1 + Y-1 + X-1 + (X-1-x);
    return X-1 + Y-1 + X-1 + Y-1 + (Y-1-y);
}

pt getXY(int cell) {
    if (cell < Y) return {0, cell};
    if (cell < Y + X - 1) return {cell - Y + 1, Y-1};
    if (cell < Y + X - 1 + Y - 1) return {X-1, Y-1 + X - 1 + Y - 1 - cell};
    return {X-1 + Y - 1 + X - 1 + Y - 1 - cell, 0};
}

int getTraintTimeToCell(int tx, int ty, int wx, int wy) {
    int t = getCell(tx, ty);
    int w = getCell(wx, wy);
    return (t - w + lap()) % lap();
}


int main() {
    int N; cin >> N;
    int timeTo;
    pt tmpTrain;
    int tmp;
    while(N--) {
        int Tx, Ty, Wx, Wy;
        cin >> Y >> X >> Tx >> Ty >> Wx >> Wy;

        // top
        timeTo = Wy;
        tmpTrain = getXY(timeTo + getCell(Tx, Ty));
        int best = getTraintTimeToCell(tmpTrain.x, tmpTrain.y, Wx, 0);

        // down
        timeTo = Y-1 - Wy;
        tmpTrain = getXY(timeTo + getCell(Tx, Ty));
        tmp = getTraintTimeToCell(tmpTrain.x, tmpTrain.y, Wx, Y-1);
        if (tmp < best) best = tmp;

        // left 
        timeTo = Wx;
        tmpTrain = getXY(timeTo + getCell(Tx, Ty));
        tmp = getTraintTimeToCell(tmpTrain.x, tmpTrain.y, 0, Wy);
        if (tmp < best) best = tmp;

        // right
        timeTo = X-1 - Wx;
        tmpTrain = getXY(timeTo + getCell(Tx, Ty));
        tmp = getTraintTimeToCell(tmpTrain.x, tmpTrain.y, X-1, Wy);
        if (tmp < best) best = tmp;

        cout << best << endl;
    }
    return 0;
}