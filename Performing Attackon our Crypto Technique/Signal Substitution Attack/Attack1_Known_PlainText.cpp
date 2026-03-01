#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <map>
#include <algorithm>

using namespace std;

// ============================================================================
// ATTACK 1: KNOWN PLAINTEXT ATTACK (Character-by-Character)
// ============================================================================

// Calculate the shift between two characters
int calculateShift(char plainChar, char cipherChar) {
    if (!isalpha(plainChar) || !isalpha(cipherChar)) {
        return -1;  // Invalid
    }
    
    // Normalize to lowercase
    char p = tolower(plainChar);
    char c = tolower(cipherChar);
    
    int pPos = p - 'a';
    int cPos = c - 'a';
    
    // Calculate shift (forward)
    int shift = (cPos - pPos + 26) % 26;
    return shift;
}

// Apply shift to a character for decryption
char applyShift(char ch, int shift) {
    if (!isalpha(ch)) return ch;
    
    if (islower(ch)) {
        int pos = ch - 'a';
        return 'a' + (pos - shift + 26) % 26;
    } else {
        int pos = ch - 'A';
        return 'A' + (pos - shift + 26) % 26;
    }
}

// Decrypt ciphertext using recovered shift stream
string decryptWithShifts(const string &ciphertext, const vector<int> &shifts) {
    string plaintext = ciphertext;
    
    for (size_t i = 0; i < ciphertext.size() && i < shifts.size(); i++) {
        plaintext[i] = applyShift(ciphertext[i], shifts[i]);
    }
    
    return plaintext;
}

// ── main attack ─────────────────────────────────────────────────────────────

int main() {
    string knownPlaintext, knownCiphertext;
    
    cout << "=== Known Plaintext Attack ===" << endl;
    cout << "This attack recovers the shift stream from known plaintext/ciphertext pairs." << endl;
    cout << endl;
    
    cout << "Enter known plaintext: ";
    getline(cin, knownPlaintext);
    
    cout << "Enter corresponding ciphertext: ";
    getline(cin, knownCiphertext);
    
    // Validate lengths match
    if (knownPlaintext.length() != knownCiphertext.length()) {
        cout << "[-] Error: Plaintext and ciphertext lengths must match!" << endl;
        return 1;
    }
    
    int n = knownPlaintext.length();
    if (n == 0) {
        cout << "[-] Error: Empty input!" << endl;
        return 1;
    }
    
    // Recover shift stream
    vector<int> shifts(n);
    int alphaCount = 0;
    
    cout << "\n[*] Recovering shift stream..." << endl;
    cout << "Position | Plain | Cipher | Shift" << endl;
    cout << "---------+-------+--------+------" << endl;
    
    for (int i = 0; i < n; i++) {
        char p = knownPlaintext[i];
        char c = knownCiphertext[i];
        
        if (isalpha(p) && isalpha(c)) {
            shifts[i] = calculateShift(p, c);
            alphaCount++;
            
            // Show first 20 shifts
            if (alphaCount <= 20) {
                cout << "   " << i << "     |   " << p << "   |   " 
                     << c << "    |  " << shifts[i] << endl;
            }
        } else {
            shifts[i] = 0;  // Non-alphabetic characters
        }
    }
    
    if (alphaCount > 20) {
        cout << "... (" << (alphaCount - 20) << " more shifts recovered)" << endl;
    }
    
    cout << "\n[+] KEY RECOVERED!" << endl;
    cout << "Total shifts recovered: " << alphaCount << endl;
    cout << "Shift stream (first 50): [";
    for (int i = 0; i < min(50, n); i++) {
        if (i > 0) cout << ", ";
        cout << shifts[i];
    }
    if (n > 50) cout << ", ...";
    cout << "]" << endl;
    
    // Verify by decrypting the known ciphertext
    string recovered = decryptWithShifts(knownCiphertext, shifts);
    bool verified = (recovered == knownPlaintext);
    
    cout << "\nVerification: " << (verified ? "PASSED ✓" : "FAILED ✗") << endl;
    
    if (!verified) {
        cout << "Expected: " << knownPlaintext << endl;
        cout << "Got:      " << recovered << endl;
        return 1;
    }
    
    // Now use the recovered key to decrypt new messages
    cout << "\n=== ATTACK PHASE ===" << endl;
    cout << "Enter another ciphertext (encrypted with same key) to decrypt: ";
    
    string targetCiphertext;
    getline(cin, targetCiphertext);
    
    if (targetCiphertext.empty()) {
        cout << "[-] No ciphertext provided." << endl;
        return 0;
    }
    
    if ((int)targetCiphertext.length() != n) {
        cout << "[-] Warning: Length mismatch! Expected " << n 
             << " characters, got " << targetCiphertext.length() << endl;
        cout << "    The cipher uses position-dependent shifts." << endl;
        cout << "    Attempting decryption anyway..." << endl;
    }
    
    // Decrypt using recovered shift stream
    string decrypted = decryptWithShifts(targetCiphertext, shifts);
    
    cout << "\n[+] DECRYPTED TEXT:" << endl;
    cout << decrypted << endl;
    
    return 0;
}