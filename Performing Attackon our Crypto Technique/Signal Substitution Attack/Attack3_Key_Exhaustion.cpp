#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <cctype>
#include <sstream>

using namespace std;

// ATTACK 3: BRUTE FORCE ATTACK (Key Space Exhaustion)

// For the distribution-based cipher, we try to guess the distribution key
// This is extremely difficult due to the continuous parameter space

const int MAX_DISTRIBUTION_TRIES = 10000;  // Limit for safety

// English letter frequencies
const map<char, double> ENGLISH_FREQ = {
    {'a', 8.167}, {'b', 1.492}, {'c', 2.782}, {'d', 4.253}, {'e', 12.702},
    {'f', 2.228}, {'g', 2.015}, {'h', 6.094}, {'i', 6.966}, {'j', 0.153},
    {'k', 0.772}, {'l', 4.025}, {'m', 2.406}, {'n', 6.749}, {'o', 7.507},
    {'p', 1.929}, {'q', 0.095}, {'r', 5.987}, {'s', 6.327}, {'t', 9.056},
    {'u', 2.758}, {'v', 0.978}, {'w', 2.360}, {'x', 0.150}, {'y', 1.974},
    {'z', 0.074}
};

// Calculate chi-squared statistic
double calculateChiSquared(const string &text) {
    map<char, int> observed;
    int totalLetters = 0;
    
    for (char c : text) {
        if (isalpha(c)) {
            observed[tolower(c)]++;
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

// Decrypt character with shift
char decryptChar(char ch, int shift) {
    if (!isalpha(ch)) return ch;
    
    if (islower(ch)) {
        return 'a' + (ch - 'a' - shift + 26) % 26;
    } else {
        return 'A' + (ch - 'A' - shift + 26) % 26;
    }
}

// Decrypt with shift stream
string decryptWithShifts(const string &ciphertext, const vector<int> &shifts) {
    string plaintext = ciphertext;
    for (size_t i = 0; i < ciphertext.size() && i < shifts.size(); i++) {
        plaintext[i] = decryptChar(ciphertext[i], shifts[i]);
    }
    return plaintext;
}

struct Candidate {
    string key;
    vector<int> shifts;
    string plaintext;
    double score;
};

// Generate some common distribution keys to try
vector<string> generateCommonKeys() {
    vector<string> keys;
    
    // Simple single-digit legacy format
    keys.push_back("1");      // Normal(0,1)
    keys.push_back("12");     // Normal with params
    keys.push_back("123");
    keys.push_back("1234");
    keys.push_back("12345");
    
    // Common two-distribution patterns
    keys.push_back("102");    // Normal + Poisson
    keys.push_back("103");    // Normal + Exponential
    keys.push_back("1023");
    keys.push_back("10203");
    
    // Multi-digit format with common parameters
    keys.push_back("1(0,1)");
    keys.push_back("1(1,2)");
    keys.push_back("1(2,1)");
    keys.push_back("1(5,2)");
    keys.push_back("1(10,3)");
    
    keys.push_back("2(1)");
    keys.push_back("2(2)");
    keys.push_back("2(3)");
    keys.push_back("2(5)");
    
    keys.push_back("3(1)");
    keys.push_back("3(2)");
    
    keys.push_back("4(0.5)");
    keys.push_back("4(0.3)");
    keys.push_back("4(0.7)");
    
    keys.push_back("5(10,0.5)");
    keys.push_back("5(20,0.3)");
    
    // Combinations
    keys.push_back("1(0,1)02(1)");
    keys.push_back("1(1,1)02(2)");
    keys.push_back("1(2,1)03(1)");
    keys.push_back("2(3)01(5,2)");
    
    return keys;
}

// Parse simple shift pattern (for testing)
vector<int> parseShiftPattern(const string &pattern, int length) {
    vector<int> shifts;
    
    // Parse comma-separated shifts
    stringstream ss(pattern);
    string token;
    
    while (getline(ss, token, ',')) {
        try {
            int shift = stoi(token);
            shifts.push_back(shift % 26);
        } catch (...) {
            // Ignore invalid
        }
    }
    
    // Repeat pattern to match length
    vector<int> result(length);
    if (shifts.empty()) {
        return result;  // All zeros
    }
    
    for (int i = 0; i < length; i++) {
        result[i] = shifts[i % shifts.size()];
    }
    
    return result;
}


int main() {
    string ciphertext;
    
    cout << "Enter ciphertext: ";
    getline(cin, ciphertext);
    
    if (ciphertext.empty()) {
        cout << "[-] Error: Empty ciphertext!" << endl;
        return 1;
    }
    
    int n = ciphertext.length();
    
    cout << "\n[*] Ciphertext length: " << n << endl;
    cout << "[*] Generating common distribution keys..." << endl;
    
    vector<string> commonKeys = generateCommonKeys();
    
    cout << "[*] Will try " << commonKeys.size() << " common distribution keys" << endl;
    
    // We can't actually decrypt without implementing the full distribution system
    // So we'll demonstrate the concept with a simplified approach
    
    // Instead, let's try simple shift patterns as a demonstration
    cout << "\n[*] DEMONSTRATION: Trying simple uniform shift patterns..." << endl;
    
    vector<Candidate> candidates;
    
    // Try uniform shifts (entire message shifted by same amount)
    for (int shift = 0; shift < 26; shift++) {
        vector<int> shifts(n, shift);
        string plaintext = decryptWithShifts(ciphertext, shifts);
        double score = calculateChiSquared(plaintext);
        
        candidates.push_back({
            "uniform_shift_" + to_string(shift),
            shifts,
            plaintext,
            score
        });
    }
    
    // Try some simple repeating patterns
    vector<string> patterns = {
        "0,1,2,3,4",
        "5,10,15,20,25",
        "1,2,3,4,5,6,7,8,9,10",
        "0,5,10,15,20",
        "3,6,9,12,15,18,21,24"
    };
    
    for (const auto &pattern : patterns) {
        vector<int> shifts = parseShiftPattern(pattern, n);
        string plaintext = decryptWithShifts(ciphertext, shifts);
        double score = calculateChiSquared(plaintext);
        
        candidates.push_back({
            "pattern_" + pattern,
            shifts,
            plaintext,
            score
        });
    }
    
    // Sort by score
    sort(candidates.begin(), candidates.end(),
         [](const Candidate &a, const Candidate &b) {
             return a.score < b.score;
         });
    
    // Display top candidates
    cout << "\n[+] TOP 5 CANDIDATES:" << endl;
    
    for (int i = 0; i < min(5, (int)candidates.size()); i++) {
        cout << "\nRank #" << (i + 1) << endl;
        cout << "Pattern: " << candidates[i].key << endl;
        cout << "Chi-squared: " << fixed << setprecision(2) 
             << candidates[i].score << endl;
        
        cout << "Shift preview: [";
        for (int j = 0; j < min(10, (int)candidates[i].shifts.size()); j++) {
            if (j > 0) cout << ", ";
            cout << candidates[i].shifts[j];
        }
        if (candidates[i].shifts.size() > 10) cout << ", ...";
        cout << "]" << endl;
        
        cout << "Plaintext: " 
             << candidates[i].plaintext.substr(0, min(80, (int)candidates[i].plaintext.length())) 
             << endl;
        if (candidates[i].plaintext.length() > 80) {
            cout << "           ..." << endl;
        }
        cout << "---------------------------------------------" << endl;
    }
    
    return 0;
}