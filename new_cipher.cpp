#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

using namespace std;

// Standard string reversal helper
void inline rev(string &str, int l, int r) {
    while (l < r) swap(str[l++], str[r--]);
}

// Rotates string to the right by k positions
void rotate(string &str, int k) {
    int n = str.length();
    if (n == 0) return;
    k %= n; 
    if (k < 0) k += n; // k maintained to be positive
    
    rev(str, 0, n-1);
    rev(str, 0, k-1);
    rev(str, k, n-1);
}

int normalizeShift(int shift, int width) {
    if (width == 0) return 0;
    shift %= width;
    if (shift < 0) shift += width;
    return shift;
}

string encrypt(string pt, vector<int> &keys) {
    if (keys.empty()) return pt;
    
    int n = static_cast<int>(pt.length());
    int rows = keys[0];
    if (rows <= 0) return pt;
    
    int circ = (n + rows - 1) / rows;
    if (circ == 0) return pt;

    int total_capacity = rows * circ;
    int padlen = total_capacity - n;
    
    for (int i = 0; i < padlen; i++) {
        pt += "x";
    }
    
    // n matches capacity
    n = pt.length();

    // 1. Fill the initial Grid
    vector<string> circ_strings(rows, string(circ, ' '));
    for (int i = 0; i < n; i++) {
        circ_strings[i/circ][i%circ] = pt[i];
    }

    // 2. Rotate Rows based on Keys
    for (int i = 0; i < rows; i++) {
        int shift = 0;
        if (i + 1 < static_cast<int>(keys.size())) shift = keys[i + 1];
        rotate(circ_strings[i], normalizeShift(shift, circ));
    }

    // 3. Transpose (Swap Rows and Cols)
    vector<string> height_strings(circ, string(rows, ' '));
    for (int i = 0; i < circ; i++) {
        for (int j = 0; j < rows; j++) {
            height_strings[i][j] = circ_strings[j][i];
        }
    }
    
    // 4. Scramble Logic (swap rows/cols diagonally)
    int k = circ / 2;
    for (int i = 0; i < circ; i++) {
        for (int j = 0; j < rows; j++) {
            swap(height_strings[i][j], height_strings[k][rows - j - 1]);
        }
        k = (k + 1) % circ;
    }

    // 5. Read out column by column
    string result = "";
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < circ; j++) {
            result += height_strings[j][i];
        }
    }

    return result;
}

string decrypt(string ct, vector<int> &keys) {
    if (keys.empty()) return ct;
    int rows = keys[0];
    if (rows <= 0) return ct;
    int n = static_cast<int>(ct.length());
    if (n == 0) return ct;
    if (n % rows != 0) return ct;

    int circ = n / rows;
    vector<string> height_strings(circ, string(rows, ' '));

    int idx = 0;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < circ; j++) {
            height_strings[j][i] = ct[idx++];
        }
    }

    // Inverse of scramble: replay swaps in reverse order.
    for (int i = circ - 1; i >= 0; i--) {
        int k = (circ / 2 + i) % circ;
        for (int j = rows - 1; j >= 0; j--) {
            swap(height_strings[i][j], height_strings[k][rows - j - 1]);
        }
    }

    // Inverse transpose.
    vector<string> circ_strings(rows, string(circ, ' '));
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < circ; j++) {
            circ_strings[i][j] = height_strings[j][i];
        }
    }

    // Inverse row rotations.
    for (int i = 0; i < rows; i++) {
        int shift = 0;
        if (i + 1 < static_cast<int>(keys.size())) shift = keys[i + 1];
        rotate(circ_strings[i], normalizeShift(-shift, circ));
    }

    string result = "";
    result.reserve(n);
    for (int i = 0; i < rows; i++) {
        result += circ_strings[i];
    }

    // Remove trailing padding used by encrypt().
    while (!result.empty() && result.back() == 'x') {
        result.pop_back();
    }
    return result;
}

int main() {
    string pt;
    cout << "Enter text to encrypt: ";
    cin >> pt; 
    
    // Key format: {num_rows, rot_row_0, rot_row_1, ...}
    vector<int> keys = {4, 1, 2, 1, 3};
    
    string ct = encrypt(pt, keys);
    cout << "Ciphertext: " << ct << endl;
    string dt = decrypt(ct, keys);
    cout << "Decrypted text: " << dt << endl;
    
    return 0;
}
