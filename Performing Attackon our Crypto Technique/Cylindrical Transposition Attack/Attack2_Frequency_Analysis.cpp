/*
 CRYPTANALYSIS ATTACK 2: Frequency Analysis Attack
 The attacker has ONLY the ciphertext (ciphertext-only scenario).
 Goal: Infer likely key or decode message using statistical properties.
 Scoring: chi-squared distance from expected English frequencies.
 Lower score = more English-like.

 Input : Ciphertext string
 Output: Best-guess key and decrypted plaintext
 */

#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <map>
#include <cmath>
#include <limits>
using namespace std;

const double EN_FREQ[26] = {
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074
};

void rev(string &s, int l, int r) { while (l < r) swap(s[l++], s[r--]); }

void rotateStr(string &s, int k) {
    int n = s.length();
    if (n == 0) return;
    k %= n; if (k < 0) k += n;
    rev(s, 0, n - 1); rev(s, 0, k - 1); rev(s, k, n - 1);
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

vector<string> partialDecrypt(const string &ctIn, int rows) {
    string ct = rowWiseToColumnWise(ctIn, rows);
    int n = ct.length();
    int circ = n / rows;

    vector<string> hs(circ, string(rows, ' '));
    int idx = 0;
    for (int i = 0; i < rows; i++)
        for (int j = 0; j < circ; j++)
            hs[j][i] = ct[idx++];

    for (int i = circ - 1; i >= 0; i--) {
        int k = (circ / 2 + i) % circ;
        if (i < k) {
            for (int j = rows - 1; j >= 0; j--)
                swap(hs[i][j], hs[k][rows - j - 1]);
        }
    }

    vector<string> cs(rows, string(circ, ' '));
    for (int i = 0; i < rows; i++)
        for (int j = 0; j < circ; j++)
            cs[i][j] = hs[j][i];

    return cs;
}

// Fitness: chi-squared score (lower = better English match)
double chiSquared(const string &s) {
    int counts[26] = {};
    int total = 0;
    for (char c : s) {
        c = tolower(c);
        if (c >= 'a' && c <= 'z') { counts[c - 'a']++; total++; }
    }
    if (total == 0) return 1e9;
    double score = 0.0;
    for (int i = 0; i < 26; i++) {
        double expected = EN_FREQ[i] * total;
        double diff = counts[i] - expected;
        score += (diff * diff) / expected;
    }
    return score;
}

// Index of Coincidence (higher = more English-like)
double indexOfCoincidence(const string &s) {
    int counts[26] = {};
    int total = 0;
    for (char c : s) {
        c = tolower(c);
        if (c >= 'a' && c <= 'z') { counts[c - 'a']++; total++; }
    }
    if (total < 2) return 0.0;
    double ic = 0.0;
    for (int i = 0; i < 26; i++) ic += counts[i] * (counts[i] - 1);
    return ic / ((double)total * (total - 1));
}

// Combined fitness (lower = better)
double fitness(const string &s) {
    // Penalise non-printable chars heavily
    int nonPrint = 0;
    for (char c : s) if (c < 32 && c != '\n' && c != '\t') nonPrint++;
    return chiSquared(s) + nonPrint * 100.0;
}

// Full decrypt given rows + shifts
string fullDecrypt(const string &ct, int rows, const vector<int> &shifts) {
    vector<string> cs = partialDecrypt(ct, rows);
    int circ = ct.length() / rows;
    string result;
    for (int i = 0; i < rows; i++) {
        string row = cs[i];
        int s = shifts[i] % circ;
        if (s < 0) s += circ;
        rotateStr(row, (circ - s) % circ); // inverse rotation
        result += row;
    }
    while (!result.empty() && result.back() == ' ') result.pop_back();
    return result;
}

// main attack

int main() {
    string ct;
    cout << "=== Frequency Analysis Attack ===" << endl;
    cout << "Enter ciphertext: ";
    getline(cin, ct);

    int ctLen = ct.length();
    if (ctLen == 0) { cout << "Empty ciphertext.\n"; return 1; }

    double bestScore = numeric_limits<double>::max();
    int bestRows = -1;
    vector<int> bestShifts;
    string bestDecrypted;

    cout << "\nAnalysing...\n";

    for (int rows = 1; rows <= ctLen; rows++) {
        if (ctLen % rows != 0) continue;
        int circ = ctLen / rows;

        vector<string> cs = partialDecrypt(ct, rows);

        vector<int> shifts(rows, 0);
        double totalScore = 0.0;

        for (int i = 0; i < rows; i++) {
            double rowBest = numeric_limits<double>::max();
            int bestS = 0;
            for (int s = 0; s < circ; s++) {
                string test = cs[i];
                rotateStr(test, (circ - s) % circ);
                double sc = fitness(test);
                if (sc < rowBest) { rowBest = sc; bestS = s; }
            }
            shifts[i] = bestS;
            totalScore += rowBest;
        }

        // Normalise by number of rows
        double avgScore = totalScore / rows;

        if (avgScore < bestScore) {
            bestScore  = avgScore;
            bestRows   = rows;
            bestShifts = shifts;
            bestDecrypted = fullDecrypt(ct, rows, shifts);
        }
    }

    if (bestRows == -1) { cout << "[-] Analysis failed.\n"; return 1; }

    cout << "\n[+] BEST KEY GUESS (lowest chi-squared fitness):" << endl;
    cout << "Key vector: {" << bestRows;
    for (int s : bestShifts) cout << ", " << s;
    cout << "}" << endl;
    cout << "Average chi-squared score: " << bestScore << endl;

    cout << "\n[+] DECRYPTED TEXT:" << endl;
    cout << bestDecrypted << endl;

    // Show top 5 candidates by rows value
    cout << "\n[*] Top candidates per 'rows' value:" << endl;
    cout << "rows | avg_chi2 | decrypted_preview" << endl;
    cout << "-----+----------+------------------------------------------" << endl;

    vector<pair<double,int>> candidates;
    for (int rows = 1; rows <= ctLen; rows++) {
        if (ctLen % rows != 0) continue;
        int circ = ctLen / rows;
        vector<string> cs = partialDecrypt(ct, rows);
        double totalScore = 0.0;
        vector<int> shifts(rows, 0);
        for (int i = 0; i < rows; i++) {
            double rowBest = 1e18;
            int bestS = 0;
            for (int s = 0; s < circ; s++) {
                string test = cs[i];
                rotateStr(test, (circ - s) % circ);
                double sc = fitness(test);
                if (sc < rowBest) { rowBest = sc; bestS = s; }
            }
            shifts[i] = bestS;
            totalScore += rowBest;
        }
        candidates.push_back({totalScore / rows, rows});
    }
    sort(candidates.begin(), candidates.end());

    int shown = 0;
    for (auto &[sc, r] : candidates) {
        if (shown++ >= 5) break;
        int circ = ctLen / r;
        vector<string> cs = partialDecrypt(ct, r);
        vector<int> sh(r, 0);
        for (int i = 0; i < r; i++) {
            double rowBest = 1e18; int bestS = 0;
            for (int s = 0; s < circ; s++) {
                string test = cs[i];
                rotateStr(test, (circ - s) % circ);
                double scc = fitness(test);
                if (scc < rowBest) { rowBest = scc; bestS = s; }
            }
            sh[i] = bestS;
        }
        string dec = fullDecrypt(ct, r, sh);
        string preview = dec.length() > 40 ? dec.substr(0, 40) + "..." : dec;
        printf("%4d | %8.2f | %s\n", r, sc, preview.c_str());
    }

    return 0;
}