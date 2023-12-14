#include <iostream>
#include <fstream>

using namespace std;

const int IN_MAX_LEN = 100;

bool isMIU(char word[]) {
    if (word[0] != 'M')
        return false;

    int iCount=0, i;
    bool isAfterI = false, iAfterMValid = true;
    for(i=0; word[i]; i++) {
        if (isAfterI) {
            isAfterI = false;
            if (word[i] == 'M')
                iAfterMValid = false;
        }
        
        if (word[i] == 'I') {
            iCount++;
            isAfterI = true;
        }
    }

    if (!iAfterMValid)
        return false;

    if (word[i-1] != 'U')
        return false;

    return !iCount || iCount & 1;
}

signed main(int argc, char** argv) {
    if (argc != 3) {
        cerr << "Wrong argument number!" << endl;
        exit(1);
    }

    fstream in, out;
    in.open(argv[1], ios::in);
    if (in.fail()) {
        cerr << "Failed opening" << argv[1] << endl;
        exit(1);
    }

    out.open(argv[2], ios::out);
    if (out.fail()) {
        cerr << "Failed opening" << argv[2] << endl;
        in.close();
        exit(1);
    }

    char tmp[IN_MAX_LEN+1];

    while (in >> tmp) {
        if (isMIU(tmp))
            out << tmp << endl;
    }

    in.close();
    out.close();
}