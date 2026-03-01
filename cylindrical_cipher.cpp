#include <iostream>
using namespace std;

string cylindrical_encrypt(string pt, int key) {
    int len = pt.length();
    
    int padlen = len % key;
    if (padlen < 0) padlen += key;

    for (int i = 0; i < padlen; i++) {
        pt += "x";
        len++;
    }

    int m = len/key;
    string result = "";

    for (int v1 = 0; v1 < len/2; v1++) {
        int v2 = v1 + (m-v1/key-1)*key + key/2;
        int subv1 = (v1 + key/2) % len;
        int subv2 = (v2 + key/2) % len;

        result = result + pt[subv1] + pt[subv2];
        v2++;
    }

    return result;
}

string cylindrical_decrypt(string ct, int key) {
    int len = ct.length();

    string new_ct = string(len, ' ');
    int v2 = len/2;
    for (int v1 = 0; v1 < len; v1+=2) {
        new_ct[v1] = ct[v1];
        new_ct[v2] = ct[v1+1];
        v2++;
    }
    cout << new_ct << endl;

    string result = "";

    v2 = len/2;
    for (int v1 = 0; v1 < len/2; v1++) {
        int subv1 = (v1 - key/2) % len;
        if (subv1 < 0) subv1 += len;
        int subv2 = (v2 - key/2) % len;
        if (subv2 < 0) subv2 += len;

        result = result + new_ct[subv1] + new_ct[subv2];
        v2++;
    }

    return result;
}

int main() {
    string pt;
    cin >> pt;
    string ct = cylindrical_encrypt(pt, 4);
    cout << ct << endl;
    string rpt = cylindrical_decrypt(ct, 4);
    cout << rpt << endl;
    return 0;
}