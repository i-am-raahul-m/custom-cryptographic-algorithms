#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <cctype>

using namespace std;

// ATTACK 2: FREQUENCY ANALYSIS ATTACK (Index of Coincidence)

// English letter frequencies (percentage)
const map<char, double> ENGLISH_FREQ = {
    {'a', 8.167}, {'b', 1.492}, {'c', 2.782}, {'d', 4.253}, {'e', 12.702},
    {'f', 2.228}, {'g', 2.015}, {'h', 6.094}, {'i', 6.966}, {'j', 0.153},
    {'k', 0.772}, {'l', 4.025}, {'m', 2.406}, {'n', 6.749}, {'o', 7.507},
    {'p', 1.929}, {'q', 0.095}, {'r', 5.987}, {'s', 6.327}, {'t', 9.056},
    {'u', 2.758}, {'v', 0.978}, {'w', 2.360}, {'x', 0.150}, {'y', 1.974},
    {'z', 0.074}
};

// Calculate chi-squared statistic (lower is better)
double calculateChiSquared(const string &text) {
    map<char, int> observed;
    int totalLetters = 0;
    
    for (char c : text) {
        if (isalpha(c)) {
            char lower = tolower(c);
            observed[lower]++;
            totalLetters++;
        }
    }
    
    if (totalLetters == 0) return 1e9;
    
    double chiSq = 0.0;
    for (char c = 'a'; c <= 'z'; c++) {
        double expected = ENGLISH_FREQ.count(c) ? 
                         (ENGLISH_FREQ.at(c) * totalLetters / 100.0) : 0.1;
        double obs = observed.count(c) ? observed[c] : 0;
        
        if (expected > 0) {
            chiSq += ((obs - expected) * (obs - expected)) / expected;
        }
    }
    
    return chiSq;
}

// Calculate Index of Coincidence
double calculateIC(const string &text) {
    map<char, int> freq;
    int n = 0;
    
    for (char c : text) {
        if (isalpha(c)) {
            freq[tolower(c)]++;
            n++;
        }
    }
    
    if (n <= 1) return 0.0;
    
    double sum = 0.0;
    for (const auto &p : freq) {
        sum += p.second * (p.second - 1);
    }
    
    return sum / (n * (n - 1));
}

// Decrypt character with shift
char decryptChar(char ch, int shift) {
    if (!isalpha(ch)) return ch;
    
    if (islower(ch)) {
        return 'a' + (ch - 'a' - shift + 26) % 26;
    } else {
        return 'A' + (ch - 'A' - shift + 26) % 26;
    }
}

// Decrypt entire text with uniform shift
string decryptWithShift(const string &ciphertext, int shift) {
    string plaintext = ciphertext;
    for (size_t i = 0; i < ciphertext.size(); i++) {
        plaintext[i] = decryptChar(ciphertext[i], shift);
    }
    return plaintext;
}

// Try to find the most common shift value
map<int, int> analyzeShifts(const string &ciphertext) {
    map<int, int> shiftFrequency;
    
    // Assume 'e' is most common in English
    map<char, int> freq;
    for (char c : ciphertext) {
        if (isalpha(c)) {
            freq[tolower(c)]++;
        }
    }
    
    // Find most common letter
    char mostCommon = 'e';
    int maxCount = 0;
    for (const auto &p : freq) {
        if (p.second > maxCount) {
            maxCount = p.second;
            mostCommon = p.first;
        }
    }
    
    // Calculate probable shift (assuming it encrypted 'e')
    int probableShift = (mostCommon - 'e' + 26) % 26;
    shiftFrequency[probableShift] = maxCount;
    
    return shiftFrequency;
}

struct Candidate {
    int shift;
    string plaintext;
    double chiSquared;
    double ic;
};

// ── main attack ─────────────────────────────────────────────────────────────

int main() {
    string ciphertext;
    
    cout << "Enter ciphertext: ";
    getline(cin, ciphertext);
    
    if (ciphertext.empty()) {
        cout << "[-] Error: Empty ciphertext!" << endl;
        return 1;
    }
    
    // Count alphabetic characters
    int alphaCount = 0;
    for (char c : ciphertext) {
        if (isalpha(c)) alphaCount++;
    }
    
    if (alphaCount == 0) {
        cout << "[-] Error: No alphabetic characters in ciphertext!" << endl;
        return 1;
    }
    
    cout << "[*] Ciphertext length: " << ciphertext.length() << endl;
    cout << "[*] Alphabetic characters: " << alphaCount << endl;
    
    // Calculate IC of ciphertext
    double ciphertextIC = calculateIC(ciphertext);
    cout << "[*] Ciphertext IC: " << fixed << setprecision(4) << ciphertextIC << endl;
    
    vector<Candidate> candidates;
    
    // Try all 26 possible shifts
    for (int shift = 0; shift < 26; shift++) {
        string plaintext = decryptWithShift(ciphertext, shift);
        double chiSq = calculateChiSquared(plaintext);
        double ic = calculateIC(plaintext);
        
        candidates.push_back({shift, plaintext, chiSq, ic});
    }
    
    // Sort by chi-squared (lower is better)
    sort(candidates.begin(), candidates.end(),
         [](const Candidate &a, const Candidate &b) {
             return a.chiSquared < b.chiSquared;
         });
    
    // Display top 5 candidates
    cout << "\n[+] TOP 5 CANDIDATES (by chi-squared fitness):" << endl;
    
    for (int i = 0; i < min(5, (int)candidates.size()); i++) {
        cout << "\nRank #" << (i + 1) << endl;
        cout << "Shift: " << candidates[i].shift << endl;
        cout << "Chi-squared: " << fixed << setprecision(2) 
             << candidates[i].chiSquared << endl;
        cout << "IC: " << fixed << setprecision(4) << candidates[i].ic << endl;
        cout << "Plaintext: " << candidates[i].plaintext.substr(0, min(80, (int)candidates[i].plaintext.length())) << endl;
        if (candidates[i].plaintext.length() > 80) {
            cout << "           ..." << endl;
        }
        cout << "---------------------------------------------" << endl;
    }
    
    // Frequency analysis
    cout << "\n[*] LETTER FREQUENCY ANALYSIS:" << endl;
    map<char, int> freq;
    for (char c : ciphertext) {
        if (isalpha(c)) {
            freq[tolower(c)]++;
        }
    }
    
    // Get top 5 most frequent letters
    vector<pair<char, int>> freqVec(freq.begin(), freq.end());
    sort(freqVec.begin(), freqVec.end(),
         [](const pair<char, int> &a, const pair<char, int> &b) {
             return a.second > b.second;
         });
    
    cout << "Most frequent letters in ciphertext:" << endl;
    for (int i = 0; i < min(5, (int)freqVec.size()); i++) {
        double percentage = 100.0 * freqVec[i].second / alphaCount;
        cout << "  " << freqVec[i].first << ": " 
             << freqVec[i].second << " (" 
             << fixed << setprecision(1) << percentage << "%)" << endl;
    }
    
    cout << "\nExpected in English: e(12.7%), t(9.1%), a(8.2%), o(7.5%), i(7.0%)" << endl;
    
    return 0;
}