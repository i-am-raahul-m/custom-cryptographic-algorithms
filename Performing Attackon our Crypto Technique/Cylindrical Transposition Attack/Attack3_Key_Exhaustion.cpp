/*
 CRYPTANALYSIS ATTACK 3: Key Exhaustion (Brute Force)
 The attacker has ONLY the ciphertext (ciphertext-only).
 Scoring: We use a combination of:
   1. Chi-squared distance from English letter frequency.
   2. Common bigram frequency reward.
   3. Space character proportion (natural English ~14% spaces).

 Input : Ciphertext string + optional max_rows/max_shifts_per_row limits
 Output: Best N decrypted candidates with their keys
 */

#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <cmath>
#include <limits>
#include <map>
#include <functional>
using namespace std;

// English letter frequencies
const double EN_FREQ[26] = {
    0.08167,0.01492,0.02782,0.04253,0.12702,0.02228,0.02015,
    0.06094,0.06966,0.00153,0.00772,0.04025,0.02406,0.06749,
    0.07507,0.01929,0.00095,0.05987,0.06327,0.09056,0.02758,
    0.00978,0.02360,0.00150,0.01974,0.00074
};

// Common English bigrams (reward for their presence)
const map<string,double> BIGRAM_REWARD = {
    {"th",0.04}, {"he",0.04}, {"in",0.03}, {"en",0.03}, {"nt",0.03},
    {"re",0.03}, {"er",0.03}, {"an",0.03}, {"ti",0.02}, {"es",0.02},
    {"on",0.02}, {"at",0.02}, {"se",0.02}, {"nd",0.02}, {"or",0.02},
    {"ar",0.02}, {"al",0.02}, {"te",0.02}, {"co",0.02}, {"de",0.02}
};

void rev(string &s, int l, int r) { while (l < r) swap(s[l++], s[r--]); }

void rotateStr(string &s, int k) {
    int n = s.length();
    if (n == 0) return;
    k %= n; if (k < 0) k += n;
    rev(s,0,n-1); rev(s,0,k-1); rev(s,k,n-1);
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
    vector<string> hs(circ, string(rows,' '));
    int idx = 0;
    for (int i = 0; i < rows; i++)
        for (int j = 0; j < circ; j++)
            hs[j][i] = ct[idx++];
    for (int i = circ-1; i >= 0; i--) {
        int k = (circ/2 + i) % circ;
        for (int j = rows-1; j >= 0; j--)
            swap(hs[i][j], hs[k][rows-j-1]);
    }
    vector<string> cs(rows, string(circ,' '));
    for (int i = 0; i < rows; i++)
        for (int j = 0; j < circ; j++)
            cs[i][j] = hs[j][i];
    return cs;
}

string applyShifts(const vector<string> &cs, int rows, int circ, const vector<int> &shifts) {
    string result;
    for (int i = 0; i < rows; i++) {
        string row = cs[i];
        int s = ((circ - shifts[i]) % circ + circ) % circ;
        rotateStr(row, s);
        result += row;
    }
    while (!result.empty() && result.back() == ' ') result.pop_back();
    return result;
}

// Scoring (lower = better; penalties for non-English)
double score(const string &s) {
    if (s.empty()) return 1e9;

    // Chi-squared on letters
    int counts[26] = {};
    int letters = 0, spaces = 0, nonPrint = 0;
    for (unsigned char c : s) {
        if (c >= 'a' && c <= 'z') { counts[c-'a']++; letters++; }
        else if (c >= 'A' && c <= 'Z') { counts[c-'A']++; letters++; }
        else if (c == ' ') spaces++;
        else if (c < 32 || c > 126) nonPrint++;
    }

    double chi2 = 0.0;
    if (letters > 0)
        for (int i = 0; i < 26; i++) {
            double exp = EN_FREQ[i] * letters;
            double diff = counts[i] - exp;
            chi2 += diff * diff / (exp > 0 ? exp : 1);
        }

    // Space ratio penalty (English ~14%)
    double spaceRatio = (double)spaces / s.length();
    double spacePenalty = abs(spaceRatio - 0.14) * 50.0;

    // Bigram reward
    string low = s;
    for (char &c : low) c = tolower(c);
    double bigramReward = 0.0;
    for (int i = 0; i + 1 < (int)low.size(); i++) {
        string bg = low.substr(i, 2);
        auto it = BIGRAM_REWARD.find(bg);
        if (it != BIGRAM_REWARD.end()) bigramReward += it->second;
    }

    // Non-printable penalty
    double nonPrintPenalty = nonPrint * 200.0;

    return chi2 + spacePenalty - bigramReward * 10.0 + nonPrintPenalty;
}

struct Result {
    double sc;
    int rows;
    vector<int> shifts;
    string decrypted;
    bool operator<(const Result &o) const { return sc < o.sc; }
};


int main() {
    string ct;
    cout << "=== Key Exhaustion (Brute Force) Attack ===" << endl;
    cout << "Enter ciphertext: ";
    getline(cin, ct);

    int ctLen = ct.length();
    if (ctLen == 0) { cout << "Empty ciphertext.\n"; return 1; }

    // User-configurable limits to prevent combinatorial explosion
    int MAX_ROWS         = 6;    // Try rows up to this value
    long long MAX_KEYS   = 500000; // Hard cap on keys per (rows) value
    int TOP_N            = 5;    // Report top N results

    cout << "Config: MAX_ROWS=" << MAX_ROWS
         << ", MAX_KEYS_PER_ROWS=" << MAX_KEYS
         << ", TOP_N=" << TOP_N << endl;
    cout << "(You can recompile with larger limits for deeper search)\n\n";

    vector<Result> results;

    for (int rows = 1; rows <= MAX_ROWS && rows <= ctLen; rows++) {
        if (ctLen % rows != 0) continue;
        int circ = ctLen / rows;

        // Estimate key space
        long long keySpace = 1;
        for (int i = 0; i < rows; i++) {
            if (keySpace > MAX_KEYS / max(circ,1)) { keySpace = MAX_KEYS + 1; break; }
            keySpace *= circ;
        }

        cout << "rows=" << rows << ", circ=" << circ
             << ", keyspace=" << (keySpace > MAX_KEYS ? ">"+to_string(MAX_KEYS)+"(capped)" : to_string(keySpace))
             << endl;

        vector<string> cs = partialDecrypt(ct, rows);

        // Per-row independent frequency guessing (fast heuristic)
        // For each row, pick the best shift independently using chi-squared.
        // Then enumerate neighbours around those best shifts for refinement.
        vector<int> bestSingleShifts(rows);
        for (int i = 0; i < rows; i++) {
            double rowBest = 1e18; int bS = 0;
            for (int s = 0; s < circ; s++) {
                string test = cs[i];
                int inv = ((circ - s) % circ + circ) % circ;
                rotateStr(test, inv);
                double sc2 = score(test);
                if (sc2 < rowBest) { rowBest = sc2; bS = s; }
            }
            bestSingleShifts[i] = bS;
        }

        // Add the greedy-best
        {
            string dec = applyShifts(cs, rows, circ, bestSingleShifts);
            results.push_back({score(dec), rows, bestSingleShifts, dec});
        }

        // Full exhaustive search (if key space is small enough)
        if (keySpace <= MAX_KEYS) {
            vector<int> shifts(rows, 0);
            long long count = 0;
            // Iterate all combinations using mixed-radix counter
            function<void(int)> enumerate = [&](int depth) {
                if (count >= MAX_KEYS) return;
                if (depth == rows) {
                    string dec = applyShifts(cs, rows, circ, shifts);
                    results.push_back({score(dec), rows, shifts, dec});
                    count++;
                    return;
                }
                for (int s = 0; s < circ; s++) {
                    shifts[depth] = s;
                    enumerate(depth + 1);
                    if (count >= MAX_KEYS) return;
                }
            };
            enumerate(0);
            cout << "  Tried " << count << " keys." << endl;
        } else {
            // Random sampling of key space
            cout << "  Key space too large, random sampling " << MAX_KEYS << " keys..." << endl;
            srand(42);
            for (long long t = 0; t < MAX_KEYS; t++) {
                vector<int> shifts(rows);
                for (int i = 0; i < rows; i++) shifts[i] = rand() % circ;
                string dec = applyShifts(cs, rows, circ, shifts);
                results.push_back({score(dec), rows, shifts, dec});
            }
        }
    }

    // Sort and deduplicate
    sort(results.begin(), results.end());

    cout << "\n[+] TOP " << TOP_N << " CANDIDATES:\n";
    cout << "==============================================\n";

    int shown = 0;
    string lastDec = "";
    for (auto &r : results) {
        if (shown >= TOP_N) break;
        if (r.decrypted == lastDec) continue; // skip duplicates
        lastDec = r.decrypted;

        cout << "\nRank #" << (shown + 1) << "  |  Score: " << r.sc << endl;
        cout << "Key: {" << r.rows;
        for (int s : r.shifts) cout << ", " << s;
        cout << "}" << endl;

        string preview = r.decrypted.length() > 80
                       ? r.decrypted.substr(0,80) + "..."
                       : r.decrypted;
        cout << "Decrypted: " << preview << endl;
        cout << "----------------------------------------------" << endl;
        shown++;
    }

    if (shown == 0) cout << "[-] No results. Try increasing MAX_ROWS or MAX_KEYS.\n";

    return 0;
}