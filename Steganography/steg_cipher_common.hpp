#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

struct PPMImage {
    int width = 0;
    int height = 0;
    int maxval = 255;
    vector<unsigned char> data;
};

static string readPPMToken(ifstream &in) {
    string token;
    char ch;
    while (in.get(ch)) {
        if (isspace(static_cast<unsigned char>(ch))) continue;
        if (ch == '#') {
            string dummy;
            getline(in, dummy);
            continue;
        }
        token.push_back(ch);
        break;
    }
    while (in.get(ch)) {
        if (isspace(static_cast<unsigned char>(ch))) break;
        token.push_back(ch);
    }
    return token;
}

static PPMImage loadPPM(const string &path) {
    ifstream in(path, ios::binary);
    if (!in) throw runtime_error("Could not open input image");

    string magic = readPPMToken(in);
    if (magic != "P6") throw runtime_error("Only binary PPM P6 images are supported");

    PPMImage img;
    img.width = stoi(readPPMToken(in));
    img.height = stoi(readPPMToken(in));
    img.maxval = stoi(readPPMToken(in));
    if (img.width <= 0 || img.height <= 0 || img.maxval != 255) {
        throw runtime_error("Invalid PPM image or unsupported maxval");
    }

    img.data.resize(static_cast<size_t>(img.width) * img.height * 3);
    in.read(reinterpret_cast<char *>(img.data.data()), static_cast<streamsize>(img.data.size()));
    if (in.gcount() != static_cast<streamsize>(img.data.size())) {
        throw runtime_error("Incomplete image data");
    }
    return img;
}

static void savePPM(const string &path, const PPMImage &img) {
    ofstream out(path, ios::binary);
    if (!out) throw runtime_error("Could not open output image");
    out << "P6\n" << img.width << " " << img.height << "\n" << img.maxval << "\n";
    out.write(reinterpret_cast<const char *>(img.data.data()), static_cast<streamsize>(img.data.size()));
}

static vector<unsigned char> uint32ToBytes(uint32_t value) {
    return {
        static_cast<unsigned char>((value >> 24) & 0xFF),
        static_cast<unsigned char>((value >> 16) & 0xFF),
        static_cast<unsigned char>((value >> 8) & 0xFF),
        static_cast<unsigned char>(value & 0xFF)
    };
}

static uint32_t bytesToUint32(const vector<unsigned char> &b, size_t start) {
    if (start + 4 > b.size()) throw runtime_error("Header too short");
    return (static_cast<uint32_t>(b[start]) << 24) |
           (static_cast<uint32_t>(b[start + 1]) << 16) |
           (static_cast<uint32_t>(b[start + 2]) << 8) |
           static_cast<uint32_t>(b[start + 3]);
}

static vector<unsigned char> extractBytes(const PPMImage &img, size_t byteCount) {
    size_t totalBits = byteCount * 8;
    if (totalBits > img.data.size()) throw runtime_error("Image does not contain enough embedded data");
    vector<unsigned char> out(byteCount, 0);
    for (size_t i = 0; i < totalBits; i++) {
        out[i / 8] = static_cast<unsigned char>((out[i / 8] << 1) | (img.data[i] & 1));
    }
    return out;
}

static void embedBytes(PPMImage &img, const vector<unsigned char> &payload) {
    size_t totalBits = payload.size() * 8;
    if (totalBits > img.data.size()) throw runtime_error("Payload too large for carrier image");
    for (size_t i = 0; i < totalBits; i++) {
        unsigned char bit = static_cast<unsigned char>((payload[i / 8] >> (7 - (i % 8))) & 1);
        img.data[i] = static_cast<unsigned char>((img.data[i] & 0xFE) | bit);
    }
}

static vector<unsigned char> stringToBytes(const string &s) {
    return vector<unsigned char>(s.begin(), s.end());
}

static string bytesToString(const vector<unsigned char> &b, size_t start = 0) {
    return string(b.begin() + static_cast<long long>(start), b.end());
}

static vector<int> parseIntList(const string &text) {
    vector<int> values;
    string token;
    stringstream ss(text);
    while (getline(ss, token, ',')) {
        string t;
        for (char ch : token) {
            if (!isspace(static_cast<unsigned char>(ch))) t.push_back(ch);
        }
        if (!t.empty()) values.push_back(stoi(t));
    }
    return values;
}

static void revString(string &str, int l, int r) {
    while (l < r) swap(str[l++], str[r--]);
}

static void rotateString(string &str, int k) {
    int n = static_cast<int>(str.length());
    if (n == 0) return;
    k %= n;
    if (k < 0) k += n;
    revString(str, 0, n - 1);
    revString(str, 0, k - 1);
    revString(str, k, n - 1);
}

static int normalizeShift(int shift, int width) {
    if (width == 0) return 0;
    shift %= width;
    if (shift < 0) shift += width;
    return shift;
}

static string columnWiseToRowWise(const string &columnWise, int rows) {
    int n = static_cast<int>(columnWise.length());
    if (rows <= 0 || n == 0 || n % rows != 0) return columnWise;
    int circ = n / rows;
    string rowWise(n, ' ');
    for (int r = 0; r < circ; r++) {
        for (int c = 0; c < rows; c++) {
            rowWise[r * rows + c] = columnWise[c * circ + r];
        }
    }
    return rowWise;
}

static string rowWiseToColumnWise(const string &rowWise, int rows) {
    int n = static_cast<int>(rowWise.length());
    if (rows <= 0 || n == 0 || n % rows != 0) return rowWise;
    int circ = n / rows;
    string columnWise(n, ' ');
    for (int r = 0; r < circ; r++) {
        for (int c = 0; c < rows; c++) {
            columnWise[c * circ + r] = rowWise[r * rows + c];
        }
    }
    return columnWise;
}

static string encryptCylindrical(string pt, vector<int> keys) {
    if (keys.empty()) return pt;
    int n = static_cast<int>(pt.length());
    int rows = keys[0];
    if (rows <= 0) return pt;
    int circ = (n + rows - 1) / rows;
    if (circ == 0) return pt;
    int totalCapacity = rows * circ;
    int padlen = totalCapacity - n;
    for (int i = 0; i < padlen; i++) pt += ' ';
    n = static_cast<int>(pt.length());

    vector<string> circStrings(rows, string(circ, ' '));
    for (int i = 0; i < n; i++) circStrings[i / circ][i % circ] = pt[i];

    for (int i = 0; i < rows; i++) {
        int shift = 0;
        if (i + 1 < static_cast<int>(keys.size())) shift = keys[i + 1];
        rotateString(circStrings[i], normalizeShift(shift, circ));
    }

    vector<string> heightStrings(circ, string(rows, ' '));
    for (int i = 0; i < circ; i++) {
        for (int j = 0; j < rows; j++) heightStrings[i][j] = circStrings[j][i];
    }

    int k = circ / 2;
    for (int i = 0; i < circ; i++) {
        for (int j = 0; j < rows; j++) swap(heightStrings[i][j], heightStrings[k][rows - j - 1]);
        k = (k + 1) % circ;
    }

    string result;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < circ; j++) result += heightStrings[j][i];
    }
    return columnWiseToRowWise(result, rows);
}

static string decryptCylindrical(string ct, vector<int> keys) {
    if (keys.empty()) return ct;
    int rows = keys[0];
    if (rows <= 0) return ct;
    ct = rowWiseToColumnWise(ct, rows);

    int n = static_cast<int>(ct.length());
    if (n == 0 || n % rows != 0) return ct;
    int circ = n / rows;
    vector<string> heightStrings(circ, string(rows, ' '));

    int idx = 0;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < circ; j++) heightStrings[j][i] = ct[idx++];
    }

    for (int i = circ - 1; i >= 0; i--) {
        int k = (circ / 2 + i) % circ;
        for (int j = rows - 1; j >= 0; j--) swap(heightStrings[i][j], heightStrings[k][rows - j - 1]);
    }

    vector<string> circStrings(rows, string(circ, ' '));
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < circ; j++) circStrings[i][j] = heightStrings[j][i];
    }

    for (int i = 0; i < rows; i++) {
        int shift = 0;
        if (i + 1 < static_cast<int>(keys.size())) shift = keys[i + 1];
        rotateString(circStrings[i], normalizeShift(-shift, circ));
    }

    string result;
    result.reserve(n);
    for (int i = 0; i < rows; i++) result += circStrings[i];
    while (!result.empty() && result.back() == ' ') result.pop_back();
    return result;
}

namespace signal_cipher {
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

static GridShape buildGridShape(int n) {
    if (n <= 0) return {0, 0};
    int cols = static_cast<int>(ceil(sqrt(static_cast<double>(n))));
    int rows = (n + cols - 1) / cols;
    return {rows, cols};
}

static string trim(const string &s) {
    size_t i = 0;
    while (i < s.size() && isspace(static_cast<unsigned char>(s[i]))) i++;
    size_t j = s.size();
    while (j > i && isspace(static_cast<unsigned char>(s[j - 1]))) j--;
    return s.substr(i, j - i);
}

static vector<double> parseNumericList(const string &text) {
    vector<double> nums;
    string token;
    stringstream ss(text);
    while (getline(ss, token, ',')) {
        string t = trim(token);
        if (t.empty()) continue;
        try {
            nums.push_back(stod(t));
        } catch (...) {
        }
    }
    return nums;
}

static vector<DistSpec> parseKey(const string &rawKey) {
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

        vector<int> digits;
        for (char ch : part) {
            if (isdigit(static_cast<unsigned char>(ch)) && ch != '0') digits.push_back(ch - '0');
        }
        if (digits.empty()) continue;
        spec.id = digits[0];
        for (size_t i = 1; i < digits.size(); i++) spec.params.push_back(static_cast<double>(digits[i]));
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
    return exp(-lambda) * pow(lambda, static_cast<double>(k)) / tgamma(k + 1.0);
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
    double lp = logChoose(n, k) + k * log(p) + (n - k) * log(1.0 - p);
    return exp(lp);
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

static double hypergeometricPmf(int populationN, int successK, int drawsN, int observedK) {
    if (populationN <= 0 || successK < 0 || drawsN < 0) return 0.0;
    if (successK > populationN || drawsN > populationN) return 0.0;
    if (observedK < 0 || observedK > successK || observedK > drawsN) return 0.0;
    int failures = populationN - successK;
    if (drawsN - observedK > failures) return 0.0;
    double top = logChoose(successK, observedK) + logChoose(failures, drawsN - observedK);
    double bot = logChoose(populationN, drawsN);
    return exp(top - bot);
}

static vector<double> normalizedProbabilities(const vector<double> &params, size_t startIdx) {
    vector<double> probs;
    for (size_t i = startIdx; i < params.size(); i++) probs.push_back(max(0.0, params[i]));
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

static double multinomialPmf(int trialsN, const vector<int> &counts, const vector<double> &probs) {
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
        if (counts[i] > 0 && probs[i] > 0.0) logProb += counts[i] * log(probs[i]);
    }
    return exp(logProb);
}

static double distributionRawValue(int distId, const vector<double> &params, int row, int col) {
    double x = (col + 0.5) * CELL_SIZE;
    double y = (row + 0.5) * CELL_SIZE;
    double radial = sqrt(x * x + y * y);

    if (distId == 1) {
        double mean = (params.size() >= 1) ? params[0] : 0.0;
        double sd = (params.size() >= 2) ? params[1] : 1.0;
        return normalPdf(radial, mean, sd);
    }
    if (distId == 2) {
        double lambda = (params.size() >= 1) ? params[0] : 1.0;
        int k = static_cast<int>(lround(radial / CELL_SIZE));
        return poissonPmf(k, lambda);
    }
    if (distId == 3) {
        double lambda = (params.size() >= 1) ? params[0] : 1.0;
        return exponentialPdf(radial, lambda);
    }
    if (distId == 4) {
        double p = (params.size() >= 1) ? params[0] : 0.5;
        int k = (static_cast<int>(floor(radial / CELL_SIZE)) + row + col) % 2;
        return bernoulliPmf(k, p);
    }
    if (distId == 5) {
        int n = (params.size() >= 1) ? max(0, static_cast<int>(lround(params[0]))) : 10;
        double p = (params.size() >= 2) ? params[1] : 0.5;
        int k = static_cast<int>(lround(radial / CELL_SIZE));
        if (n > 0) k %= (n + 1);
        return binomialPmf(n, k, p);
    }
    if (distId == 6) {
        double p = (params.size() >= 1) ? params[0] : 0.5;
        int k = static_cast<int>(lround(radial / CELL_SIZE)) + 1;
        return geometricPmf(k, p);
    }
    if (distId == 7) {
        int a = (params.size() >= 1) ? static_cast<int>(lround(params[0])) : 0;
        int b = (params.size() >= 2) ? static_cast<int>(lround(params[1])) : 9;
        int k = static_cast<int>(lround(radial / CELL_SIZE));
        return discreteUniformPmf(k, a, b);
    }
    if (distId == 8) {
        int N = (params.size() >= 1) ? max(1, static_cast<int>(lround(params[0]))) : 20;
        int K = (params.size() >= 2) ? max(0, static_cast<int>(lround(params[1]))) : 7;
        int n = (params.size() >= 3) ? max(0, static_cast<int>(lround(params[2]))) : 5;
        int k = static_cast<int>(lround(radial / CELL_SIZE));
        if (n > 0) k %= (n + 1);
        return hypergeometricPmf(N, K, n, k);
    }
    if (distId == 9) {
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
        vector<double> probs = normalizedProbabilities(params, 0);
        if (probs.empty()) return 0.0;
        int k = static_cast<int>(probs.size());
        int cat = (static_cast<int>(lround(radial / CELL_SIZE)) + row + col) % k;
        return probs[cat];
    }
    return 0.0;
}

static vector<int> buildShiftStream(int n, const string &rawKey) {
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

static char shiftAlpha(char ch, int shift) {
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

static string encryptSignal(const string &plaintext, const string &rawKey) {
    int n = static_cast<int>(plaintext.size());
    vector<int> shifts = buildShiftStream(n, rawKey);
    string ciphertext = plaintext;
    for (int i = 0; i < n; i++) ciphertext[i] = shiftAlpha(plaintext[i], shifts[i]);
    return ciphertext;
}

static string decryptSignal(const string &ciphertext, const string &rawKey) {
    int n = static_cast<int>(ciphertext.size());
    vector<int> shifts = buildShiftStream(n, rawKey);
    string plaintext = ciphertext;
    for (int i = 0; i < n; i++) plaintext[i] = shiftAlpha(ciphertext[i], -shifts[i]);
    return plaintext;
}
}

static string encryptByCipher(int cipherId, const string &message, const string &keyText) {
    if (cipherId == 1) return signal_cipher::encryptSignal(message, keyText);
    if (cipherId == 2) return encryptCylindrical(message, parseIntList(keyText));
    throw runtime_error("Unsupported cipher id");
}

static string decryptByCipher(int cipherId, const string &message, const string &keyText) {
    if (cipherId == 1) return signal_cipher::decryptSignal(message, keyText);
    if (cipherId == 2) return decryptCylindrical(message, parseIntList(keyText));
    throw runtime_error("Unsupported cipher id");
}