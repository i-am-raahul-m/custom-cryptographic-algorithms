/*
 CRYPTANALYSIS ATTACK 3: Key Exhaustion / Brute-Force (FIXED)
 =============================================================
 The Signal Substitution cipher derives a unique per-position shift from
 one or more statistical distributions evaluated on a 2-D grid.  To mount
 a true brute-force attack we must:

   (a) Re-implement the cipher's full buildShiftStream() machinery so that
       candidate keys produce the ACTUAL keystream, not a Caesar proxy.
   (b) Search the key space systematically:
         Phase 1 – Dictionary of common single-distribution keys
         Phase 2 – Systematic parameter grid over all 10 distributions
         Phase 3 – Combination keys (two distributions composed)
         Phase 4 – Random parameter sampling (last-resort wide search)

 All candidates are scored with quadgram fitness (scoring.h).
 The TOP N decryptions are reported.

 Note: The true key space is infinite (continuous real parameters), so
 exhaustive search is infeasible.  This attack demonstrates the best
 practically achievable coverage and quantifies the resistance of the
 cipher design.
*/

#include <cmath>
#include <cctype>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include "../../scoring.h"

using namespace std;

// ============================================================================
// CIPHER INTERNALS (verbatim from signal_substitution_cipher.cpp)
// Required to compute the authentic shift stream for any candidate key.
// ============================================================================

namespace cipher {

const double CELL_SIZE = 0.25;
const double PI_VAL    = 3.14159265358979323846;

struct DistSpec { int id; vector<double> params; };
struct GridShape { int rows; int cols; };

GridShape buildGridShape(int n) {
    if (n <= 0) return {0, 0};
    int cols = (int)ceil(sqrt((double)n));
    int rows = (n + cols - 1) / cols;
    return {rows, cols};
}

static string trim(const string &s) {
    size_t i = 0;
    while (i < s.size() && isspace((unsigned char)s[i])) i++;
    size_t j = s.size();
    while (j > i && isspace((unsigned char)s[j - 1])) j--;
    return s.substr(i, j - i);
}

static vector<double> parseNumericList(const string &text) {
    vector<double> nums;
    string token;
    stringstream ss(text);
    while (getline(ss, token, ',')) {
        string t = trim(token);
        if (t.empty()) continue;
        try { nums.push_back(stod(t)); } catch (...) {}
    }
    return nums;
}

vector<DistSpec> parseKey(const string &rawKey) {
    vector<DistSpec> specs;
    string current;
    int parenDepth = 0;
    vector<string> segments;

    for (char ch : rawKey) {
        if (ch == '(') parenDepth++;
        if (ch == ')') parenDepth = max(0, parenDepth - 1);
        if (ch == '0' && parenDepth == 0) {
            string seg = trim(current);
            if (!seg.empty()) segments.push_back(seg);
            current.clear();
        } else {
            current.push_back(ch);
        }
    }
    string seg = trim(current);
    if (!seg.empty()) segments.push_back(seg);

    for (const string &part : segments) {
        if (part.empty()) continue;
        DistSpec spec;
        size_t lp = part.find('('), rp = part.rfind(')');
        if (lp != string::npos && rp != string::npos && rp > lp) {
            string idText = trim(part.substr(0, lp));
            if (idText.empty()) continue;
            try { spec.id = stoi(idText); } catch (...) { continue; }
            spec.params = parseNumericList(part.substr(lp + 1, rp - lp - 1));
            specs.push_back(spec);
            continue;
        }
        // Legacy single-digit parser
        vector<int> digits;
        for (char ch : part)
            if (isdigit((unsigned char)ch) && ch != '0')
                digits.push_back(ch - '0');
        if (digits.empty()) continue;
        spec.id = digits[0];
        for (size_t i = 1; i < digits.size(); i++)
            spec.params.push_back((double)digits[i]);
        specs.push_back(spec);
    }
    return specs;
}

static double normalPdf(double x, double mean, double sd) {
    if (sd <= 0.0) return 0.0;
    double z = (x - mean) / sd;
    return exp(-0.5 * z * z) / (sd * sqrt(2.0 * PI_VAL));
}
static double poissonPmf(int k, double lambda) {
    if (lambda <= 0.0 || k < 0) return 0.0;
    return exp(-lambda) * pow(lambda, (double)k) / tgamma(k + 1.0);
}
static double exponentialPdf(double x, double lambda) {
    if (lambda <= 0.0 || x < 0.0) return 0.0;
    return lambda * exp(-lambda * x);
}
static double bernoulliPmf(int k, double p) {
    if (p < 0.0 || p > 1.0) return 0.0;
    if (k == 0) return 1.0 - p;
    if (k == 1) return p;
    return 0.0;
}
static double logChoose(int n, int k) {
    if (n < 0 || k < 0 || k > n) return -1e300;
    return lgamma(n + 1.0) - lgamma(k + 1.0) - lgamma(n - k + 1.0);
}
static double binomialPmf(int n, int k, double p) {
    if (n < 0 || k < 0 || k > n || p < 0.0 || p > 1.0) return 0.0;
    if (p == 0.0) return (k == 0) ? 1.0 : 0.0;
    if (p == 1.0) return (k == n) ? 1.0 : 0.0;
    return exp(logChoose(n, k) + k * log(p) + (n - k) * log(1.0 - p));
}
static double geometricPmf(int k, double p) {
    if (k < 1 || p <= 0.0 || p > 1.0) return 0.0;
    return pow(1.0 - p, k - 1) * p;
}
static double discreteUniformPmf(int k, int a, int b) {
    if (a > b) swap(a, b);
    if (k < a || k > b) return 0.0;
    return 1.0 / (b - a + 1.0);
}
static double hypergeometricPmf(int N, int K, int n, int k) {
    if (N <= 0 || K < 0 || n < 0) return 0.0;
    if (K > N || n > N) return 0.0;
    if (k < 0 || k > K || k > n) return 0.0;
    int failures = N - K;
    if (n - k > failures) return 0.0;
    return exp(logChoose(K, k) + logChoose(failures, n - k) - logChoose(N, n));
}
static vector<double> normalizedProbabilities(const vector<double> &params, size_t start) {
    vector<double> probs;
    for (size_t i = start; i < params.size(); i++) probs.push_back(max(0.0, params[i]));
    if (probs.empty()) return probs;
    double sum = 0.0;
    for (double p : probs) sum += p;
    if (sum <= 0.0) { double u = 1.0 / probs.size(); for (double &p : probs) p = u; return probs; }
    for (double &p : probs) p /= sum;
    return probs;
}
static double multinomialPmf(int trialsN, const vector<int> &counts, const vector<double> &probs) {
    if (trialsN < 0 || counts.size() != probs.size() || counts.empty()) return 0.0;
    int sumC = 0; for (int c : counts) { if (c < 0) return 0.0; sumC += c; }
    if (sumC != trialsN) return 0.0;
    double lp = lgamma(trialsN + 1.0);
    for (size_t i = 0; i < counts.size(); i++) {
        if (probs[i] < 0.0 || probs[i] > 1.0) return 0.0;
        if (probs[i] == 0.0 && counts[i] > 0) return 0.0;
        lp -= lgamma(counts[i] + 1.0);
        if (counts[i] > 0 && probs[i] > 0.0) lp += counts[i] * log(probs[i]);
    }
    return exp(lp);
}

static double distributionRawValue(int distId, const vector<double> &params, int row, int col) {
    double x = (col + 0.5) * CELL_SIZE;
    double y = (row + 0.5) * CELL_SIZE;
    double radial = sqrt(x * x + y * y);

    if (distId == 1) {
        double mean = (params.size() >= 1) ? params[0] : 0.0;
        double sd   = (params.size() >= 2) ? params[1] : 1.0;
        return normalPdf(radial, mean, sd);
    }
    if (distId == 2) {
        double lambda = (params.size() >= 1) ? params[0] : 1.0;
        int k = (int)lround(radial / CELL_SIZE);
        return poissonPmf(k, lambda);
    }
    if (distId == 3) {
        double lambda = (params.size() >= 1) ? params[0] : 1.0;
        return exponentialPdf(radial, lambda);
    }
    if (distId == 4) {
        double p = (params.size() >= 1) ? params[0] : 0.5;
        int k = ((int)floor(radial / CELL_SIZE) + row + col) % 2;
        return bernoulliPmf(k, p);
    }
    if (distId == 5) {
        int    n = (params.size() >= 1) ? max(0, (int)lround(params[0])) : 10;
        double p = (params.size() >= 2) ? params[1] : 0.5;
        int k = (int)lround(radial / CELL_SIZE);
        if (n > 0) k %= (n + 1);
        return binomialPmf(n, k, p);
    }
    if (distId == 6) {
        double p = (params.size() >= 1) ? params[0] : 0.5;
        int k = (int)lround(radial / CELL_SIZE) + 1;
        return geometricPmf(k, p);
    }
    if (distId == 7) {
        int a = (params.size() >= 1) ? (int)lround(params[0]) : 0;
        int b = (params.size() >= 2) ? (int)lround(params[1]) : 9;
        int k = (int)lround(radial / CELL_SIZE);
        return discreteUniformPmf(k, a, b);
    }
    if (distId == 8) {
        int N = (params.size() >= 1) ? max(1, (int)lround(params[0])) : 20;
        int K = (params.size() >= 2) ? max(0, (int)lround(params[1])) :  7;
        int n = (params.size() >= 3) ? max(0, (int)lround(params[2])) :  5;
        int k = (int)lround(radial / CELL_SIZE);
        if (n > 0) k %= (n + 1);
        return hypergeometricPmf(N, K, n, k);
    }
    if (distId == 9) {
        int n = (params.size() >= 1) ? max(0, (int)lround(params[0])) : 6;
        vector<double> probs = normalizedProbabilities(params, 1);
        if (probs.empty()) return 0.0;
        int m = (int)probs.size();
        vector<int> counts(m, 0);
        int remaining = n;
        int seed = (int)lround(radial / CELL_SIZE) + row * 7 + col * 11;
        for (int i = 0; i < m - 1; i++) {
            int take = (remaining > 0) ? ((seed + 3 * i) % (remaining + 1)) : 0;
            counts[i] = take; remaining -= take;
        }
        counts[m - 1] = remaining;
        return multinomialPmf(n, counts, probs);
    }
    if (distId == 10) {
        vector<double> probs = normalizedProbabilities(params, 0);
        if (probs.empty()) return 0.0;
        int k = (int)probs.size();
        int cat = ((int)lround(radial / CELL_SIZE) + row + col) % k;
        return probs[cat];
    }
    return 0.0;
}

// Build the per-character shift stream for a given key string and message length.
vector<int> buildShiftStream(int n, const string &rawKey) {
    vector<int> shifts(n, 0);
    if (n <= 0) return shifts;
    vector<DistSpec> specs = parseKey(rawKey);
    if (specs.empty()) return shifts;

    GridShape shape = buildGridShape(n);
    vector<double> combined(n, 0.0);
    int usedDists = 0;

    for (const auto &spec : specs) {
        vector<double> raw(n, 0.0);
        double mn = 1e300, mx = -1e300;
        for (int idx = 0; idx < n; idx++) {
            int r = idx / shape.cols, c = idx % shape.cols;
            double v = distributionRawValue(spec.id, spec.params, r, c);
            raw[idx] = v;
            if (v < mn) mn = v;
            if (v > mx) mx = v;
        }
        double range = mx - mn;
        for (int idx = 0; idx < n; idx++) {
            double norm = (range > 1e-12) ? (raw[idx] - mn) / range : 0.0;
            combined[idx] += norm;
        }
        usedDists++;
    }

    for (int i = 0; i < n; i++) {
        int s = (int)lround(combined[i] / usedDists * 1000.0) % 26;
        if (s < 0) s += 26;
        shifts[i] = s;
    }
    return shifts;
}

// Decrypt ciphertext using a key string (replicates the cipher's decrypt).
string decrypt(const string &ciphertext, const string &rawKey) {
    int n = (int)ciphertext.size();
    vector<int> shifts = buildShiftStream(n, rawKey);
    string plaintext = ciphertext;
    for (int i = 0; i < n; i++) {
        unsigned char c = (unsigned char)ciphertext[i];
        if (isalpha(c)) {
            int base = islower(c) ? 'a' : 'A';
            plaintext[i] = (char)(base + (c - base - shifts[i] + 26) % 26);
        }
    }
    return plaintext;
}

} // namespace cipher

// ============================================================================
// ATTACK INFRASTRUCTURE
// ============================================================================

struct Candidate {
    string key;
    string plaintext;
    double fitness;
    bool operator<(const Candidate &o) const { return fitness > o.fitness; }
};

// Evaluate a key string against the ciphertext; returns a Candidate.
Candidate tryKey(const string &ct, const string &key) {
    string pt = cipher::decrypt(ct, key);
    return {key, pt, scoring::evaluateFitness(pt)};
}

// ── Key generators ──────────────────────────────────────────────────────────

// Phase 1: hand-crafted dictionary of common distribution key strings.
vector<string> dictionaryKeys() {
    return {
        // Single distributions – legacy format
        "1", "12", "123", "1234", "2", "3", "4", "5", "6", "7", "8", "9",
        // Normal(mean, sd) grid
        "1(0,1)", "1(0,0.5)", "1(0,2)", "1(0,5)",
        "1(1,1)", "1(1,2)", "1(2,1)", "1(2,2)", "1(5,2)", "1(10,3)",
        // Poisson(lambda) grid
        "2(0.5)", "2(1)", "2(2)", "2(3)", "2(5)", "2(10)",
        // Exponential(lambda) grid
        "3(0.5)", "3(1)", "3(2)", "3(3)", "3(5)", "3(10)",
        // Bernoulli(p) grid
        "4(0.1)", "4(0.2)", "4(0.3)", "4(0.5)", "4(0.7)", "4(0.9)",
        // Binomial(n, p) grid
        "5(5,0.3)", "5(5,0.5)", "5(10,0.3)", "5(10,0.5)", "5(20,0.5)",
        // Geometric(p)
        "6(0.2)", "6(0.5)", "6(0.8)",
        // Discrete Uniform(a, b)
        "7(0,9)", "7(0,25)", "7(1,5)",
        // Hypergeometric
        "8(20,7,5)", "8(50,10,8)",
        // Multinomial
        "9(6,0.2,0.3,0.5)",
        // Categorical
        "10(0.1,0.2,0.3,0.4)",
    };
}

// Phase 2: systematic parameter grid – single distributions with fine-grained params.
vector<string> gridKeys() {
    vector<string> keys;
    // Normal: sweep mean in {0,1,2,5,10} × sd in {0.5,1,1.5,2,3,5}
    for (double mean : {0.0, 0.5, 1.0, 2.0, 5.0, 10.0}) {
        for (double sd : {0.25, 0.5, 1.0, 1.5, 2.0, 3.0, 5.0}) {
            ostringstream oss;
            oss << "1(" << mean << "," << sd << ")";
            keys.push_back(oss.str());
        }
    }
    // Poisson: lambda 0.5 to 20 in steps of 0.5
    for (double l = 0.5; l <= 20.0; l += 0.5) {
        ostringstream oss; oss << "2(" << l << ")"; keys.push_back(oss.str());
    }
    // Exponential: lambda 0.1 to 10 in steps of 0.5
    for (double l = 0.1; l <= 10.0; l += 0.5) {
        ostringstream oss; oss << "3(" << l << ")"; keys.push_back(oss.str());
    }
    // Bernoulli: p 0.05 to 0.95 in steps of 0.05
    for (double p = 0.05; p <= 0.95; p += 0.05) {
        ostringstream oss; oss << "4(" << p << ")"; keys.push_back(oss.str());
    }
    // Geometric: p 0.05 to 0.95 in steps of 0.05
    for (double p = 0.05; p <= 0.95; p += 0.05) {
        ostringstream oss; oss << "6(" << p << ")"; keys.push_back(oss.str());
    }
    return keys;
}

// Phase 3: two-distribution combination keys.
vector<string> combinationKeys() {
    vector<string> keys;
    // Normal + Poisson
    for (auto &ns : {"1(0,1)", "1(1,1)", "1(2,1)", "1(5,2)"})
        for (auto &ps : {"2(1)", "2(2)", "2(5)"}) {
            keys.push_back(string(ns) + "0" + string(ps));
        }
    // Normal + Exponential
    for (auto &ns : {"1(0,1)", "1(1,1)"})
        for (auto &es : {"3(1)", "3(2)", "3(5)"})
            keys.push_back(string(ns) + "0" + string(es));
    // Poisson + Exponential
    for (auto &ps : {"2(1)", "2(2)", "2(5)"})
        for (auto &es : {"3(1)", "3(2)"})
            keys.push_back(string(ps) + "0" + string(es));
    // Bernoulli + Normal
    for (auto &bs : {"4(0.3)", "4(0.5)", "4(0.7)"})
        for (auto &ns : {"1(0,1)", "1(2,1)"})
            keys.push_back(string(bs) + "0" + string(ns));
    return keys;
}

// Phase 4: random parameter sampling.
vector<string> randomKeys(int count, unsigned seed = 42) {
    srand(seed);
    vector<string> keys;
    const int distIds[] = {1, 2, 3, 4, 6};
    for (int t = 0; t < count; t++) {
        int id = distIds[rand() % 5];
        ostringstream oss;
        if (id == 1) {
            double mean = (rand() % 201 - 50) * 0.1;   // -5 to 15
            double sd   = 0.1 + (rand() % 100) * 0.1;  // 0.1 to 10
            oss << "1(" << mean << "," << sd << ")";
        } else if (id == 2) {
            double l = 0.1 + (rand() % 200) * 0.1;
            oss << "2(" << l << ")";
        } else if (id == 3) {
            double l = 0.1 + (rand() % 100) * 0.1;
            oss << "3(" << l << ")";
        } else if (id == 4) {
            double p = 0.01 + (rand() % 98) * 0.01;
            oss << "4(" << p << ")";
        } else {
            double p = 0.01 + (rand() % 98) * 0.01;
            oss << "6(" << p << ")";
        }
        keys.push_back(oss.str());
    }
    return keys;
}

// ── Main ──────────────────────────────────────────────────────────────────

int main() {
    string ciphertext;
    cout << "=== Signal Substitution: Key Exhaustion Attack (Brute-Force) ==="
         << endl;
    cout << "Enter ciphertext: ";
    getline(cin, ciphertext);
    if (ciphertext.empty()) { cerr << "[-] Empty ciphertext.\n"; return 1; }

    int TOP_N            = 5;
    int RANDOM_KEY_COUNT = 2000;

    cout << "\n[*] Ciphertext length  : " << ciphertext.size() << endl;
    cout << "[*] Attack phases:" << endl;
    cout << "    Phase 1 - Dictionary keys      (common distribution keys)" << endl;
    cout << "    Phase 2 - Parameter grid       (single-distribution sweep)" << endl;
    cout << "    Phase 3 - Combination keys     (two-distribution composed)" << endl;
    cout << "    Phase 4 - Random sampling      (" << RANDOM_KEY_COUNT
         << " random parameter sets)" << endl;
    cout << endl;

    vector<Candidate> results;
    results.reserve(4096);

    // Phase 1
    {
        auto keys = dictionaryKeys();
        cout << "[Phase 1] Dictionary   : " << keys.size() << " keys... ";
        cout.flush();
        for (const auto &k : keys) results.push_back(tryKey(ciphertext, k));
        cout << "done." << endl;
    }

    // Phase 2
    {
        auto keys = gridKeys();
        cout << "[Phase 2] Parameter grid: " << keys.size() << " keys... ";
        cout.flush();
        for (const auto &k : keys) results.push_back(tryKey(ciphertext, k));
        cout << "done." << endl;
    }

    // Phase 3
    {
        auto keys = combinationKeys();
        cout << "[Phase 3] Combinations : " << keys.size() << " keys... ";
        cout.flush();
        for (const auto &k : keys) results.push_back(tryKey(ciphertext, k));
        cout << "done." << endl;
    }

    // Phase 4
    {
        auto keys = randomKeys(RANDOM_KEY_COUNT);
        cout << "[Phase 4] Random sample: " << keys.size() << " keys... ";
        cout.flush();
        for (const auto &k : keys) results.push_back(tryKey(ciphertext, k));
        cout << "done." << endl;
    }

    cout << "\n[*] Total candidates evaluated: " << results.size() << endl;

    // Sort descending by fitness
    sort(results.begin(), results.end());

    // Report top N (deduplicate by plaintext)
    cout << "\n[+] TOP " << TOP_N << " CANDIDATES (by quadgram fitness):"
         << endl;
    cout << string(70, '=') << endl;

    int shown = 0;
    string lastPt;
    for (const auto &r : results) {
        if (shown >= TOP_N) break;
        if (r.plaintext == lastPt) continue;  // skip duplicates
        lastPt = r.plaintext;

        string preview = ((int)r.plaintext.size() > 80)
                       ? r.plaintext.substr(0, 80) + "..."
                       : r.plaintext;

        cout << "\nRank #" << (shown + 1)
             << "  |  Fitness: " << fixed << setprecision(2) << r.fitness
             << endl;
        cout << "Key      : " << r.key << endl;
        cout << "Plaintext: " << preview << endl;
        cout << string(70, '-') << endl;
        shown++;
    }

    if (shown == 0)
        cout << "[-] No candidates produced. Check ciphertext format.\n";

    // Summary note for research
    cout << "\n[NOTE] The Signal Substitution cipher's key space is infinite"
            " (continuous real\n"
            "parameters, 10 distribution families, arbitrary compositions)."
            " This search\n"
            "covered ~" << results.size() << " points. A low best-fitness"
            " score across all candidates\n"
            "demonstrates quantitative resistance to key-exhaustion attacks.\n";

    return 0;
}