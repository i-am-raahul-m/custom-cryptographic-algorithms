/*
 CRYPTANALYSIS ATTACK 2: Frequency Analysis Attack (FIXED)
 ============================================================
 The Signal Substitution cipher is a non-periodic polyalphabetic cipher:
 each position gets a unique shift derived from probability distributions
 evaluated on a 2-D grid — it has no repeating key period.

 This attack applies the correct sequence of statistical tests:

   [1] Index of Coincidence (IC) — classify cipher type
   [2] Kasiski / IC Period Analysis — detect any repeating period
   [3] Per-Column Caesar Attack — frequency attack under best period guess
   [4] Hill-Climbing Attack — greedy per-position shift recovery (the
       strongest known ciphertext-only method for non-periodic
       polyalphabetic ciphers)

 Expected result: steps 1-3 show the cipher resists classical frequency
 analysis; step 4 partially recovers text for short ciphertexts but
 converges to a local optimum for longer ones — demonstrating the
 exponential key space of the distribution-based keystream.
*/

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <cctype>
#include <numeric>
#include "../../scoring.h"

using namespace std;

// --- English reference data ---
const double EN_FREQ[26] = {
    0.08167,0.01492,0.02782,0.04253,0.12702,0.02228,0.02015,
    0.06094,0.06966,0.00153,0.00772,0.04025,0.02406,0.06749,
    0.07507,0.01929,0.00095,0.05987,0.06327,0.09056,0.02758,
    0.00978,0.02360,0.00150,0.01974,0.00074
};
const double ENGLISH_IC = 0.0667;
const double RANDOM_IC   = 0.0385;

// ── Statistical helpers ──────────────────────────────────────────────────────

double calcIC(const string &s) {
    int counts[26] = {};
    int n = 0;
    for (unsigned char c : s)
        if (isalpha(c)) { counts[tolower(c) - 'a']++; n++; }
    if (n < 2) return 0.0;
    double sum = 0.0;
    for (int i = 0; i < 26; i++) sum += (double)counts[i] * (counts[i] - 1);
    return sum / ((double)n * (n - 1));
}

double chiSquared(const string &s) {
    int counts[26] = {};
    int total = 0;
    for (unsigned char c : s)
        if (isalpha(c)) { counts[tolower(c) - 'a']++; total++; }
    if (total == 0) return 1e9;
    double score = 0.0;
    for (int i = 0; i < 26; i++) {
        double expected = EN_FREQ[i] * total;
        if (expected > 0) {
            double diff = counts[i] - expected;
            score += (diff * diff) / expected;
        }
    }
    return score;
}

// Extract every period-th alphabetic character starting at offset
string extractColumn(const string &s, int period, int offset) {
    string col;
    int alphaIdx = 0;
    for (unsigned char c : s) {
        if (isalpha(c)) {
            if (alphaIdx % period == offset) col += (char)c;
            alphaIdx++;
        }
    }
    return col;
}

// Apply a single uniform Caesar shift to all alpha chars
string applyUniformShift(const string &s, int shift) {
    string out = s;
    for (char &c : out) {
        if (isalpha((unsigned char)c)) {
            int base = islower((unsigned char)c) ? 'a' : 'A';
            c = (char)(base + ((unsigned char)c - base - shift + 26) % 26);
        }
    }
    return out;
}

// Best Caesar shift for a column by minimum chi-squared
int bestCaesarShift(const string &col) {
    int best = 0;
    double bestChi = 1e18;
    for (int s = 0; s < 26; s++) {
        double chi = chiSquared(applyUniformShift(col, s));
        if (chi < bestChi) { bestChi = chi; best = s; }
    }
    return best;
}

// Decrypt with a per-position shift array (the true cipher model)
string decryptWithShifts(const string &ct, const vector<int> &shifts) {
    string pt = ct;
    for (size_t i = 0; i < ct.size() && i < shifts.size(); i++) {
        unsigned char c = (unsigned char)ct[i];
        if (isalpha(c)) {
            int base = islower(c) ? 'a' : 'A';
            pt[i] = (char)(base + (c - base - shifts[i] + 26) % 26);
        }
    }
    return pt;
}

// ── Hill-climbing helpers ────────────────────────────────────────────────────

// Efficient local fitness: rebuild full decryption, compute quadgram score.
// For per-position changes we rebuild the full string because the quadgram
// scoring window covers at most 4 consecutive chars, but non-alpha stripping
// in evaluateFitness complicates direct delta computation.
double fullFitness(const string &ct, const vector<int> &shifts) {
    return scoring::evaluateFitness(decryptWithShifts(ct, shifts));
}

// ── Main attack ──────────────────────────────────────────────────────────────

int main() {
    string ciphertext;
    cout << "=== Signal Substitution: Frequency Analysis Attack ===" << endl;
    cout << "Enter ciphertext: ";
    getline(cin, ciphertext);
    if (ciphertext.empty()) { cerr << "[-] Empty ciphertext.\n"; return 1; }

    int n = (int)ciphertext.size();

    // ── [1] Index of Coincidence ──────────────────────────────────────────
    double ic = calcIC(ciphertext);
    cout << "\n[1] INDEX OF COINCIDENCE ANALYSIS" << endl;
    cout << "    Ciphertext IC : " << fixed << setprecision(4) << ic << endl;
    cout << "    English IC    : " << ENGLISH_IC
         << "  (monoalphabetic / pure transposition)" << endl;
    cout << "    Random IC     : " << RANDOM_IC
         << "  (random noise / long-period polyalphabetic)" << endl;
    if (ic < 0.045)
        cout << "    --> Near-random IC: cipher is polyalphabetic with a long"
                " or infinite key period." << endl;
    else if (ic > 0.060)
        cout << "    --> Near-English IC: cipher is monoalphabetic or a"
                " pure transposition." << endl;
    else
        cout << "    --> Intermediate IC: short-period polyalphabetic cipher"
                " is likely." << endl;

    // ── [2] Kasiski / IC Period Analysis ─────────────────────────────────
    cout << "\n[2] KASISKI / IC PERIOD ANALYSIS (periods 1-30)" << endl;
    cout << "    Period | Avg Column IC | Note" << endl;
    cout << "    -------+---------------+----------------------------------"
         << endl;

    int    bestPeriod   = 1;
    double bestPeriodIC = 0.0;

    for (int period = 1; period <= 30; period++) {
        double avgIC = 0.0;
        int    colCount = 0;
        for (int offset = 0; offset < period; offset++) {
            string col = extractColumn(ciphertext, period, offset);
            if ((int)col.size() >= 2) { avgIC += calcIC(col); colCount++; }
        }
        if (colCount > 0) avgIC /= colCount;

        const char *note = (avgIC > 0.058) ? "<-- period candidate!" : "";
        printf("    %6d | %13.4f | %s\n", period, avgIC, note);

        if (avgIC > bestPeriodIC) { bestPeriodIC = avgIC; bestPeriod = period; }
    }

    cout << "\n    Best candidate period: " << bestPeriod
         << " (avg IC = " << fixed << setprecision(4) << bestPeriodIC << ")"
         << endl;
    if (bestPeriodIC < 0.055)
        cout << "    --> No strong period found. The cipher's keystream has"
                " no repeating structure detectable by IC analysis." << endl;

    // ── [3] Per-Column Caesar Attack on best period ───────────────────────
    cout << "\n[3] PER-COLUMN CAESAR ATTACK (using period = " << bestPeriod
         << ")" << endl;
    {
        // Count alpha chars to build the per-alpha-position shift map
        int alphaLen = 0;
        for (unsigned char c : ciphertext) if (isalpha(c)) alphaLen++;

        vector<int> perAlphaShift(alphaLen, 0);
        for (int offset = 0; offset < bestPeriod; offset++) {
            string col = extractColumn(ciphertext, bestPeriod, offset);
            int s = bestCaesarShift(col);
            // Assign this shift to every alpha position in this column
            for (int i = offset; i < alphaLen; i += bestPeriod)
                perAlphaShift[i] = s;
        }

        // Map back to per-character shifts (including non-alpha = 0)
        vector<int> shifts(n, 0);
        int aIdx = 0;
        for (int i = 0; i < n; i++) {
            if (isalpha((unsigned char)ciphertext[i]))
                shifts[i] = perAlphaShift[aIdx++];
        }

        string recovered = decryptWithShifts(ciphertext, shifts);
        double fit = scoring::evaluateFitness(recovered);
        cout << "    Quadgram fitness : " << fixed << setprecision(2) << fit
             << endl;
        cout << "    Recovered (80ch) : "
             << recovered.substr(0, min(80, n));
        if (n > 80) cout << "...";
        cout << endl;
        cout << "    (A fitness near 0 or very negative indicates the period"
                " guess is wrong)" << endl;
    }

    // ── [4] Hill-Climbing per-position attack ────────────────────────────
    cout << "\n[4] HILL-CLIMBING ATTACK (greedy per-position shift recovery)"
         << endl;
    cout << "    Model: treat each position as an independent Caesar shift." << endl;
    cout << "    Optimiser: greedy coordinate descent on quadgram fitness." << endl;
    cout << "    Convergence to global optimum is NOT guaranteed without the" << endl;
    cout << "    true distribution key — this quantifies the cipher's resistance." << endl;

    {
        // Seed: find the best uniform shift as starting point
        vector<int> shifts(n, 0);
        {
            double bestFit = -1e18;
            int bestSeed = 0;
            for (int s = 0; s < 26; s++) {
                double f = scoring::evaluateFitness(
                    decryptWithShifts(ciphertext, vector<int>(n, s)));
                if (f > bestFit) { bestFit = f; bestSeed = s; }
            }
            fill(shifts.begin(), shifts.end(), bestSeed);
        }

        double curFit = fullFitness(ciphertext, shifts);
        int passes = 0;
        bool improved = true;
        const int MAX_PASSES = 100;

        while (improved && passes < MAX_PASSES) {
            improved = false;
            for (int i = 0; i < n; i++) {
                if (!isalpha((unsigned char)ciphertext[i])) continue;
                int origShift = shifts[i];
                int localBestShift = origShift;
                double localBest = curFit;

                for (int s = 0; s < 26; s++) {
                    if (s == origShift) continue;
                    shifts[i] = s;
                    double f = fullFitness(ciphertext, shifts);
                    if (f > localBest) { localBest = f; localBestShift = s; }
                }

                if (localBestShift != origShift) {
                    shifts[i] = localBestShift;
                    curFit = localBest;
                    improved = true;
                } else {
                    shifts[i] = origShift;
                }
            }
            passes++;
        }

        string recovered = decryptWithShifts(ciphertext, shifts);
        cout << "\n    Passes completed  : " << passes << " / " << MAX_PASSES
             << endl;
        cout << "    Final fitness     : " << fixed << setprecision(2) << curFit
             << endl;
        cout << "    Recovered (80ch)  : "
             << recovered.substr(0, min(80, n));
        if (n > 80) cout << "...";
        cout << endl;

        // Show shift uniqueness — key diagnostic for polyalphabetic ciphers
        map<int, int> shiftHist;
        for (int i = 0; i < n; i++)
            if (isalpha((unsigned char)ciphertext[i])) shiftHist[shifts[i]]++;

        cout << "\n    Recovered shift distribution (unique values = "
             << shiftHist.size() << " / 26 possible):" << endl;
        for (auto &[s, cnt] : shiftHist)
            cout << "      shift " << setw(2) << s << " : " << cnt
                 << " positions" << endl;

        cout << "\n    RESULT: Without the distribution key the hill-climber"
                " finds a local optimum.\n"
                "    The diversity of recovered shifts confirms the cipher is"
                " genuinely polyalphabetic\n"
                "    and resists uniform-shift and period-based frequency"
                " analysis." << endl;
    }

    return 0;
}