#include <cmath>
#include <cctype>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

namespace {
const double CELL_SIZE = 0.25;
const double PI_VAL = 3.14159265358979323846;

struct DistSpec {
    int id;
    vector<double> params;
};

struct GridShape {
    int rows;
    int cols;
};

GridShape buildGridShape(int n) {
    if (n <= 0) return {0, 0};
    int cols = static_cast<int>(ceil(sqrt(static_cast<double>(n))));
    int rows = (n + cols - 1) / cols;
    return {rows, cols};
}

string trim(const string &s) {
    size_t i = 0;
    while (i < s.size() && isspace(static_cast<unsigned char>(s[i]))) i++;
    size_t j = s.size();
    while (j > i && isspace(static_cast<unsigned char>(s[j - 1]))) j--;
    return s.substr(i, j - i);
}

vector<double> parseNumericList(const string &text) {
    vector<double> nums;
    string token;
    stringstream ss(text);

    while (getline(ss, token, ',')) {
        string t = trim(token);
        if (t.empty()) continue;
        try {
            nums.push_back(stod(t));
        } catch (...) {
            // Ignore malformed token.
        }
    }
    return nums;
}

vector<DistSpec> parseKey(const string &rawKey) {
    vector<DistSpec> specs;

    // New format (multi-digit friendly): 1(12,30)02(4)
    // Legacy format still supported: 123024
    // Distribution groups are separated by '0' at top level.
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

        size_t lp = part.find('(');
        size_t rp = part.rfind(')');

        if (lp != string::npos && rp != string::npos && rp > lp) {
            string idText = trim(part.substr(0, lp));
            if (idText.empty()) continue;
            try {
                spec.id = stoi(idText);
            } catch (...) {
                continue;
            }
            string inside = part.substr(lp + 1, rp - lp - 1);
            spec.params = parseNumericList(inside);
            specs.push_back(spec);
            continue;
        }

        // Legacy parser: digits only, single-digit id and params.
        vector<int> digits;
        for (char ch : part) {
            if (isdigit(static_cast<unsigned char>(ch)) && ch != '0') {
                digits.push_back(ch - '0');
            }
        }
        if (digits.empty()) continue;
        spec.id = digits[0];
        for (size_t i = 1; i < digits.size(); i++) {
            spec.params.push_back(static_cast<double>(digits[i]));
        }
        specs.push_back(spec);
    }

    return specs;
}

double normalPdf(double x, double mean, double sd) {
    if (sd <= 0.0) return 0.0;
    double z = (x - mean) / sd;
    return exp(-0.5 * z * z) / (sd * sqrt(2.0 * PI_VAL));
}

double poissonPmf(int k, double lambda) {
    if (lambda <= 0.0 || k < 0) return 0.0;
    return exp(-lambda) * pow(lambda, static_cast<double>(k)) / tgamma(k + 1.0);
}

double exponentialPdf(double x, double lambda) {
    if (lambda <= 0.0 || x < 0.0) return 0.0;
    return lambda * exp(-lambda * x);
}

double bernoulliPmf(int k, double p) {
    if (p < 0.0 || p > 1.0) return 0.0;
    if (k == 0) return 1.0 - p;
    if (k == 1) return p;
    return 0.0;
}

double logChoose(int n, int k) {
    if (n < 0 || k < 0 || k > n) return -1e300;
    return lgamma(n + 1.0) - lgamma(k + 1.0) - lgamma(n - k + 1.0);
}

double binomialPmf(int n, int k, double p) {
    if (n < 0 || k < 0 || k > n || p < 0.0 || p > 1.0) return 0.0;
    if (p == 0.0) return (k == 0) ? 1.0 : 0.0;
    if (p == 1.0) return (k == n) ? 1.0 : 0.0;
    double lp = logChoose(n, k) + k * log(p) + (n - k) * log(1.0 - p);
    return exp(lp);
}

double geometricPmf(int k, double p) {
    // Supported form: P(X=k)=(1-p)^(k-1)p, k>=1
    if (k < 1 || p <= 0.0 || p > 1.0) return 0.0;
    return pow(1.0 - p, k - 1) * p;
}

double discreteUniformPmf(int k, int a, int b) {
    if (a > b) swap(a, b);
    if (k < a || k > b) return 0.0;
    return 1.0 / (b - a + 1.0);
}

double hypergeometricPmf(int populationN, int successK, int drawsN, int observedK) {
    if (populationN <= 0 || successK < 0 || drawsN < 0) return 0.0;
    if (successK > populationN || drawsN > populationN) return 0.0;
    if (observedK < 0 || observedK > successK || observedK > drawsN) return 0.0;
    int failures = populationN - successK;
    if (drawsN - observedK > failures) return 0.0;

    double top = logChoose(successK, observedK) + logChoose(failures, drawsN - observedK);
    double bot = logChoose(populationN, drawsN);
    return exp(top - bot);
}

vector<double> normalizedProbabilities(const vector<double> &params, size_t startIdx) {
    vector<double> probs;
    for (size_t i = startIdx; i < params.size(); i++) {
        probs.push_back(max(0.0, params[i]));
    }
    if (probs.empty()) return probs;

    double sum = 0.0;
    for (double p : probs) sum += p;
    if (sum <= 0.0) {
        double uniform = 1.0 / probs.size();
        for (double &p : probs) p = uniform;
        return probs;
    }

    for (double &p : probs) p /= sum;
    return probs;
}

double multinomialPmf(int trialsN, const vector<int> &counts, const vector<double> &probs) {
    if (trialsN < 0 || counts.size() != probs.size() || counts.empty()) return 0.0;
    int sumCounts = 0;
    for (int c : counts) {
        if (c < 0) return 0.0;
        sumCounts += c;
    }
    if (sumCounts != trialsN) return 0.0;

    double logProb = lgamma(trialsN + 1.0);
    for (size_t i = 0; i < counts.size(); i++) {
        if (probs[i] < 0.0 || probs[i] > 1.0) return 0.0;
        if (probs[i] == 0.0 && counts[i] > 0) return 0.0;
        logProb -= lgamma(counts[i] + 1.0);
        if (counts[i] > 0 && probs[i] > 0.0) {
            logProb += counts[i] * log(probs[i]);
        }
    }
    return exp(logProb);
}

double distributionRawValue(
    int distId,
    const vector<double> &params,
    int row,
    int col
) {
    double x = (col + 0.5) * CELL_SIZE;
    double y = (row + 0.5) * CELL_SIZE;
    double radial = sqrt(x * x + y * y);

    if (distId == 1) {
        // Normal(mean, sd): params=[mean,sd]
        double mean = (params.size() >= 1) ? params[0] : 0.0;
        double sd = (params.size() >= 2) ? params[1] : 1.0;
        return normalPdf(radial, mean, sd);
    }
    if (distId == 2) {
        // Poisson(lambda): params=[lambda]
        double lambda = (params.size() >= 1) ? params[0] : 1.0;
        int k = static_cast<int>(lround(radial / CELL_SIZE));
        return poissonPmf(k, lambda);
    }
    if (distId == 3) {
        // Exponential(lambda): params=[lambda]
        double lambda = (params.size() >= 1) ? params[0] : 1.0;
        return exponentialPdf(radial, lambda);
    }
    if (distId == 4) {
        // Bernoulli(p): params=[p]
        double p = (params.size() >= 1) ? params[0] : 0.5;
        int k = (static_cast<int>(floor(radial / CELL_SIZE)) + row + col) % 2;
        return bernoulliPmf(k, p);
    }
    if (distId == 5) {
        // Binomial(n,p): params=[n,p]
        int n = (params.size() >= 1) ? max(0, static_cast<int>(lround(params[0]))) : 10;
        double p = (params.size() >= 2) ? params[1] : 0.5;
        int k = static_cast<int>(lround(radial / CELL_SIZE));
        if (n > 0) k %= (n + 1);
        return binomialPmf(n, k, p);
    }
    if (distId == 6) {
        // Geometric(p): params=[p]
        double p = (params.size() >= 1) ? params[0] : 0.5;
        int k = static_cast<int>(lround(radial / CELL_SIZE)) + 1;
        return geometricPmf(k, p);
    }
    if (distId == 7) {
        // Discrete Uniform(a,b): params=[a,b]
        int a = (params.size() >= 1) ? static_cast<int>(lround(params[0])) : 0;
        int b = (params.size() >= 2) ? static_cast<int>(lround(params[1])) : 9;
        int k = static_cast<int>(lround(radial / CELL_SIZE));
        return discreteUniformPmf(k, a, b);
    }
    if (distId == 8) {
        // Hypergeometric(N,K,n): params=[N,K,n]
        int N = (params.size() >= 1) ? max(1, static_cast<int>(lround(params[0]))) : 20;
        int K = (params.size() >= 2) ? max(0, static_cast<int>(lround(params[1]))) : 7;
        int n = (params.size() >= 3) ? max(0, static_cast<int>(lround(params[2]))) : 5;
        int k = static_cast<int>(lround(radial / CELL_SIZE));
        if (n > 0) k %= (n + 1);
        return hypergeometricPmf(N, K, n, k);
    }
    if (distId == 9) {
        // Multinomial(n,p1,p2,...,pm): params=[n,p1,p2,...]
        int n = (params.size() >= 1) ? max(0, static_cast<int>(lround(params[0]))) : 6;
        vector<double> probs = normalizedProbabilities(params, 1);
        if (probs.empty()) return 0.0;
        int m = static_cast<int>(probs.size());

        vector<int> counts(m, 0);
        int remaining = n;
        int seed = static_cast<int>(lround(radial / CELL_SIZE)) + row * 7 + col * 11;
        for (int i = 0; i < m - 1; i++) {
            int take = (remaining > 0) ? ((seed + 3 * i) % (remaining + 1)) : 0;
            counts[i] = take;
            remaining -= take;
        }
        counts[m - 1] = remaining;
        return multinomialPmf(n, counts, probs);
    }
    if (distId == 10) {
        // Categorical(p1,p2,...,pk): params=[p1,p2,...]
        vector<double> probs = normalizedProbabilities(params, 0);
        if (probs.empty()) return 0.0;
        int k = static_cast<int>(probs.size());
        int cat = (static_cast<int>(lround(radial / CELL_SIZE)) + row + col) % k;
        return probs[cat];
    }

    return 0.0;
}

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
        double mn = 1e300;
        double mx = -1e300;

        for (int idx = 0; idx < n; idx++) {
            int r = idx / shape.cols;
            int c = idx % shape.cols;
            double v = distributionRawValue(spec.id, spec.params, r, c);
            raw[idx] = v;
            if (v < mn) mn = v;
            if (v > mx) mx = v;
        }

        double range = mx - mn;
        for (int idx = 0; idx < n; idx++) {
            double norm = 0.0;
            if (range > 1e-12) norm = (raw[idx] - mn) / range;
            combined[idx] += norm;
        }
        usedDists++;
    }

    if (usedDists == 0) return shifts;

    for (int i = 0; i < n; i++) {
        double normalized = combined[i] / usedDists;
        int s = static_cast<int>(lround(normalized * 1000.0)) % 26;
        if (s < 0) s += 26;
        shifts[i] = s;
    }

    return shifts;
}

char shiftAlpha(char ch, int shift) {
    if (!isalpha(static_cast<unsigned char>(ch))) return ch;

    if (islower(static_cast<unsigned char>(ch))) {
        int base = 'a';
        int idx = ch - base;
        return static_cast<char>(base + (idx + shift + 26) % 26);
    }

    int base = 'A';
    int idx = ch - base;
    return static_cast<char>(base + (idx + shift + 26) % 26);
}
} // namespace

string encrypt(const string &plaintext, const string &rawKey) {
    int n = static_cast<int>(plaintext.size());
    vector<int> shifts = buildShiftStream(n, rawKey);

    string ciphertext = plaintext;
    for (int i = 0; i < n; i++) {
        ciphertext[i] = shiftAlpha(plaintext[i], shifts[i]);
    }
    return ciphertext;
}

string decrypt(const string &ciphertext, const string &rawKey) {
    int n = static_cast<int>(ciphertext.size());
    vector<int> shifts = buildShiftStream(n, rawKey);

    string plaintext = ciphertext;
    for (int i = 0; i < n; i++) {
        plaintext[i] = shiftAlpha(ciphertext[i], -shifts[i]);
    }
    return plaintext;
}

int main() {
    string plaintext;
    string key;

    cout << "Enter plaintext: ";
    getline(cin, plaintext);
    cout << "Distribution IDs: 1=Normal, 2=Poisson, 3=Exponential, 4=Bernoulli, "
         << "5=Binomial, 6=Geometric, 7=DiscreteUniform, 8=Hypergeometric, "
         << "9=Multinomial, 10=Categorical\n";
        
    cout << "Enter key (legacy: 123024, multi-digit: 1(12,30)02(4)): ";
    getline(cin, key);

    string ciphertext = encrypt(plaintext, key);
    string recovered = decrypt(ciphertext, key);

    cout << "Ciphertext: " << ciphertext << "\n";
    cout << "Decrypted : " << recovered << "\n";

    return 0;
}
