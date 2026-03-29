/*
 CRYPTANALYSIS ATTACK 1: Known Plaintext Attack
 The attacker knows BOTH the plaintext and its corresponding ciphertext.
 Goal: Recover the key vector {rows, rot0, rot1, ...}
 Input: Ciphertext string + Known plaintext string
 Output: Recovered key vector
 */

#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
using namespace std;

void rev(string &s, int l, int r) { while (l < r) swap(s[l++], s[r--]); }

void rotateStr(string &s, int k) {
    int n = s.length();
    if (n == 0) return;
    k %= n;
    if (k < 0) k += n;
    rev(s, 0, n - 1);
    rev(s, 0, k - 1);
    rev(s, k, n - 1);
}

int normalizeShift(int shift, int width) {
    if (width == 0) return 0;
    shift %= width;
    if (shift < 0) shift += width;
    return shift;
}

string rowWiseToColumnWise(const string &rw, int rows) {
    int n = rw.length();
    if (rows <= 0 || n == 0 || n % rows != 0) return rw;
    int circ = n / rows;
    string cw(n, ' ');
    for (int r = 0; r < circ; r++)
        for (int c = 0; c < rows; c++)
            cw[c * circ + r] = rw[r * rows + c];
    return cw;
}

// Returns circ_strings (rows x circ) after undoing scramble+transpose but BEFORE undoing row rotations.
vector<string> partialDecrypt(const string &ctIn, int rows) {
    string ct = rowWiseToColumnWise(ctIn, rows);
    int n = ct.length();
    int circ = n / rows;

    // Rebuild height_strings from column-by-column readout
    vector<string> hs(circ, string(rows, ' '));
    int idx = 0;
    for (int i = 0; i < rows; i++)
        for (int j = 0; j < circ; j++)
            hs[j][i] = ct[idx++];

    // Inverse scramble
    for (int i = circ - 1; i >= 0; i--) {
        int k = (circ / 2 + i) % circ;
        if (i < k) {
            for (int j = rows - 1; j >= 0; j--)
                swap(hs[i][j], hs[k][rows - j - 1]);
        }
    }

    // Inverse transpose → circ_strings
    vector<string> cs(rows, string(circ, ' '));
    for (int i = 0; i < rows; i++)
        for (int j = 0; j < circ; j++)
            cs[i][j] = hs[j][i];

    return cs; // each cs[i] is row i AFTER rotation but BEFORE inverse rotation
}

// main attack

int main() {
    string ct, pt;
    cout << "=== Known Plaintext Attack ===" << endl;
    cout << "Enter ciphertext: ";
    getline(cin, ct);
    cout << "Enter known plaintext: ";
    getline(cin, pt);

    int ctLen = ct.length();
    if (ctLen == 0) { cout << "Empty ciphertext.\n"; return 1; }

    bool found = false;

    // Try every possible rows value from 1 to ctLen
    for (int rows = 1; rows <= ctLen && !found; rows++) {
        // circ must be integer
        if (ctLen % rows != 0) continue;
        int circ = ctLen / rows;

        // Build expected padded plaintext rows
        string padded = pt;
        while ((int)padded.length() < ctLen) padded += ' ';
        if ((int)padded.length() != ctLen) continue;

        vector<string> ptRows(rows, string(circ, ' '));
        for (int i = 0; i < rows; i++)
            for (int j = 0; j < circ; j++)
                ptRows[i][j] = padded[i * circ + j];

        // Get the rotated rows from ciphertext
        vector<string> cs = partialDecrypt(ct, rows);

        // For each row, find the rotation shift that maps cs[i] → ptRows[i]
        vector<int> shifts(rows, -1);
        bool rowsMatch = true;
        for (int i = 0; i < rows && rowsMatch; i++) {
            bool shiftFound = false;
            for (int s = 0; s < circ; s++) {
                string test = cs[i];
                rotateStr(test, normalizeShift(-s, circ));
                if (test == ptRows[i]) {
                    shifts[i] = s;
                    shiftFound = true;
                    break;
                }
            }
            if (!shiftFound) rowsMatch = false;
        }

        if (rowsMatch) {
            found = true;
            cout << "\n[+] KEY RECOVERED!" << endl;
            cout << "Key vector: {" << rows;
            for (int i = 0; i < rows; i++) cout << ", " << shifts[i];
            cout << "}" << endl;

            // Verify by re-encrypting with recovered key
            cout << "\nVerification:" << endl;
            cout << "  rows  = " << rows << endl;
            cout << "  circ  = " << circ << endl;
            for (int i = 0; i < rows; i++)
                cout << "  row[" << i << "] rotation = " << shifts[i] << endl;
        }
    }

    if (!found)
        cout << "\n[-] Could not recover key. Ensure plaintext/ciphertext match.\n";

    return 0;
}