/*
 * Crypt_Analyzer.cpp — Comprehensive Cryptanalysis Test Harness
 * ==============================================================
 * Tests both ciphers x 3 attacks x 3 sizes x 10 inputs = 180 logged runs.
 *
 * Ciphers : Cylindrical Transposition, Signal Substitution
 * Attacks : Known-Plaintext (KPA), Frequency Analysis, Key Exhaustion
 * Sizes   : Small (20-50), Medium (80-150), Large (300-550) chars
 *
 * Build : g++ -std=c++17 -O2 -o Crypt_Analyzer Crypt_Analyzer.cpp
 * Run   : ./Crypt_Analyzer
 * Log   : cryptanalysis_log.txt  (created/overwritten each run)
 */

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <vector>
#include <functional>
#include <numeric>
#include "scoring.h"

using namespace std;
using clk = chrono::steady_clock;

// ============================================================================
// LOGGER
// ============================================================================
class Logger {
    ofstream f_;
public:
    Logger(const string& path) : f_(path) {
        if (!f_.is_open()) cerr << "WARN: cannot open log file " << path << "\n";
        auto t = chrono::system_clock::to_time_t(chrono::system_clock::now());
        w(string(80,'#') + "\n# CRYPTANALYSIS LOG — Generated: " + ctime(&t) +
          "# 180 runs: 2 ciphers x 3 attacks x 3 sizes x 10 inputs\n" +
          string(80,'#') + "\n\n");
    }
    void w(const string& s){ cout << s; if(f_.is_open()) f_ << s; }
    void wl(const string& s=""){ w(s+"\n"); }
    void sep(char c='=',int n=80){ wl(string(n,c)); }
};

// ============================================================================
// RANDOM TEXT GENERATION
// ============================================================================
namespace textgen {
    const vector<string> POOL = {
        "the","quick","brown","fox","jumps","over","lazy","dog","and",
        "cryptography","cipher","attacks","security","encryption","algorithm",
        "secret","message","plaintext","research","frequency","brute","force",
        "key","recovery","statistical","distribution","signal","transposition",
        "substitution","analysis","mathematics","probability","information",
        "entropy","modern","classical","defense","vulnerability","secure",
        "network","protocol","system","design","implementation","normal",
        "poisson","exponential","bernoulli","geometric","with","for","this",
        "from","into","about","which","have","been","will","they","their",
        "when","more","some","than","these","also","can","data","stream"
    };

    string make(int minLen, int maxLen, mt19937& rng){
        uniform_int_distribution<size_t> wi(0, POOL.size()-1);
        string t;
        while((int)t.size() < maxLen){
            if(!t.empty()) t+=' ';
            t += POOL[wi(rng)];
            if((int)t.size() >= minLen && t.back()!=' ') {
                // check if adding next word would exceed maxLen; if so stop
                size_t ni = wi(rng);
                if((int)(t.size()+1+POOL[ni].size()) > maxLen) break;
            }
        }
        if((int)t.size() > maxLen) t = t.substr(0,maxLen);
        return t;
    }
}

// ============================================================================
// SHARED CIPHER UTILITIES
// ============================================================================
namespace util {
    void rev(string& s, int l, int r){ while(l<r) swap(s[l++],s[r--]); }

    void rotateStr(string& s, int k){
        int n=s.size(); if(!n) return;
        k%=n; if(k<0) k+=n;
        rev(s,0,n-1); rev(s,0,k-1); rev(s,k,n-1);
    }

    int normShift(int s, int w){ if(!w) return 0; s%=w; if(s<0)s+=w; return s; }

    string col2row(const string& cw, int rows){
        int n=cw.size(); if(rows<=0||!n||n%rows) return cw;
        int circ=n/rows; string rw(n,' ');
        for(int r=0;r<circ;r++) for(int c=0;c<rows;c++) rw[r*rows+c]=cw[c*circ+r];
        return rw;
    }
    string row2col(const string& rw, int rows){
        int n=rw.size(); if(rows<=0||!n||n%rows) return rw;
        int circ=n/rows; string cw(n,' ');
        for(int r=0;r<circ;r++) for(int c=0;c<rows;c++) cw[c*circ+r]=rw[r*rows+c];
        return cw;
    }

    double calcIC(const string& s){
        int cnt[26]={},n=0;
        for(unsigned char c:s) if(isalpha(c)){cnt[tolower(c)-'a']++;n++;}
        if(n<2)return 0;
        double sum=0; for(int i=0;i<26;i++) sum+=cnt[i]*(cnt[i]-1);
        return sum/((double)n*(n-1));
    }

    // Levenshtein similarity ratio [0,1]
    double similarity(const string& a, const string& b){
        int m=a.size(), n=b.size();
        if(!m&&!n)return 1.0;
        vector<vector<int>> dp(m+1,vector<int>(n+1));
        for(int i=0;i<=m;i++) dp[i][0]=i;
        for(int j=0;j<=n;j++) dp[0][j]=j;
        for(int i=1;i<=m;i++) for(int j=1;j<=n;j++)
            dp[i][j]= (tolower(a[i-1])==tolower(b[j-1])) ?
                dp[i-1][j-1] : 1+min({dp[i-1][j],dp[i][j-1],dp[i-1][j-1]});
        return 1.0 - (double)dp[m][n]/max(m,n);
    }
}

// ============================================================================
// CYLINDRICAL TRANSPOSITION CIPHER
// ============================================================================
namespace cyl {
    using namespace util;

    string encrypt(string pt, const vector<int>& keys){
        if(keys.empty()) return pt;
        int rows=keys[0]; if(rows<=0) return pt;
        int n=pt.size();
        int circ=(n+rows-1)/rows;
        int cap=rows*circ;
        while((int)pt.size()<cap) pt+=' ';
        n=pt.size();

        vector<string> cs(rows,string(circ,' '));
        for(int i=0;i<n;i++) cs[i/circ][i%circ]=pt[i];

        for(int i=0;i<rows;i++){
            int sh=0; if(i+1<(int)keys.size()) sh=keys[i+1];
            rotateStr(cs[i], normShift(sh,circ));
        }

        vector<string> hs(circ,string(rows,' '));
        for(int i=0;i<circ;i++) for(int j=0;j<rows;j++) hs[i][j]=cs[j][i];

        int k=circ/2;
        for(int i=0;i<circ;i++){
            if(i<k) for(int j=0;j<rows;j++) swap(hs[i][j],hs[k][rows-j-1]);
            k=(k+1)%circ;
        }

        string result;
        for(int i=0;i<rows;i++) for(int j=0;j<circ;j++) result+=hs[j][i];
        return col2row(result,rows);
    }

    string decrypt(string ct, const vector<int>& keys){
        if(keys.empty()) return ct;
        int rows=keys[0]; if(rows<=0) return ct;
        ct=row2col(ct,rows);
        int n=ct.size(); if(!n||n%rows) return ct;
        int circ=n/rows;

        vector<string> hs(circ,string(rows,' '));
        int idx=0;
        for(int i=0;i<rows;i++) for(int j=0;j<circ;j++) hs[j][i]=ct[idx++];

        for(int i=circ-1;i>=0;i--){
            int k=(circ/2+i)%circ;
            if(i<k) for(int j=rows-1;j>=0;j--) swap(hs[i][j],hs[k][rows-j-1]);
        }

        vector<string> cs(rows,string(circ,' '));
        for(int i=0;i<rows;i++) for(int j=0;j<circ;j++) cs[i][j]=hs[j][i];

        for(int i=0;i<rows;i++){
            int sh=0; if(i+1<(int)keys.size()) sh=keys[i+1];
            rotateStr(cs[i], normShift(-sh,circ));
        }

        string result;
        for(int i=0;i<rows;i++) result+=cs[i];
        while(!result.empty()&&result.back()==' ') result.pop_back();
        return result;
    }

    // Partial decrypt: undo everything EXCEPT per-row rotation → returns rows
    vector<string> partial(const string& ctIn, int rows){
        string ct=row2col(ctIn,rows);
        int n=ct.size(), circ=n/rows;
        vector<string> hs(circ,string(rows,' '));
        int idx=0;
        for(int i=0;i<rows;i++) for(int j=0;j<circ;j++) hs[j][i]=ct[idx++];
        for(int i=circ-1;i>=0;i--){
            int k=(circ/2+i)%circ;
            if(i<k) for(int j=rows-1;j>=0;j--) swap(hs[i][j],hs[k][rows-j-1]);
        }
        vector<string> cs(rows,string(circ,' '));
        for(int i=0;i<rows;i++) for(int j=0;j<circ;j++) cs[i][j]=hs[j][i];
        return cs;
    }

    string applyShifts(const vector<string>& cs,int rows,int circ,const vector<int>& shifts){
        string r;
        for(int i=0;i<rows;i++){
            string row=cs[i];
            rotateStr(row,((circ-shifts[i])%circ+circ)%circ);
            r+=row;
        }
        while(!r.empty()&&r.back()==' ') r.pop_back();
        return r;
    }

    string keyStr(const vector<int>& k){
        string s="{"+to_string(k[0]);
        for(int i=1;i<(int)k.size();i++) s+=","+to_string(k[i]);
        return s+"}";
    }
}

// ============================================================================
// SIGNAL SUBSTITUTION CIPHER
// ============================================================================
namespace sig {
    const double CELL=0.25, PI=3.14159265358979323846;

    struct DS{ int id; vector<double> p; };

    static string trim_(const string& s){
        size_t i=0; while(i<s.size()&&isspace((unsigned char)s[i]))i++;
        size_t j=s.size(); while(j>i&&isspace((unsigned char)s[j-1]))j--;
        return s.substr(i,j-i);
    }

    static vector<double> parseNums(const string& t){
        vector<double> v; string tok; stringstream ss(t);
        while(getline(ss,tok,',')){
            string x=trim_(tok); if(x.empty()) continue;
            try{v.push_back(stod(x));}catch(...){}
        }
        return v;
    }

    vector<DS> parseKey(const string& raw){
        vector<DS> specs; string cur; int depth=0;
        vector<string> segs;
        for(char c:raw){
            if(c=='(') depth++;
            if(c==')') depth=max(0,depth-1);
            if(c=='0'&&!depth){ string s=trim_(cur); if(!s.empty())segs.push_back(s); cur.clear();}
            else cur+=c;
        }
        { string s=trim_(cur); if(!s.empty())segs.push_back(s); }
        for(auto& part:segs){
            if(part.empty()) continue;
            DS ds;
            size_t lp=part.find('('),rp=part.rfind(')');
            if(lp!=string::npos&&rp!=string::npos&&rp>lp){
                string id=trim_(part.substr(0,lp)); if(id.empty())continue;
                try{ds.id=stoi(id);}catch(...){continue;}
                ds.p=parseNums(part.substr(lp+1,rp-lp-1));
                specs.push_back(ds); continue;
            }
            vector<int> digs;
            for(char c:part) if(isdigit((unsigned char)c)&&c!='0') digs.push_back(c-'0');
            if(digs.empty())continue;
            ds.id=digs[0];
            for(size_t i=1;i<digs.size();i++) ds.p.push_back((double)digs[i]);
            specs.push_back(ds);
        }
        return specs;
    }

    static double nPdf(double x,double m,double s){
        if(s<=0)return 0;
        double z=(x-m)/s;
        return exp(-0.5*z*z)/(s*sqrt(2*PI));
    }
    static double pPmf(int k,double l){
        if(l<=0||k<0)return 0;
        return exp(-l)*pow(l,k)/tgamma(k+1.0);
    }
    static double ePdf(double x,double l){ return (l<=0||x<0)?0:l*exp(-l*x); }
    static double bePmf(int k,double p){
        if(p<0||p>1)return 0;
        return k==0?1-p:k==1?p:0;
    }
    static double lC(int n,int k){
        if(n<0||k<0||k>n)return-1e300;
        return lgamma(n+1.)-lgamma(k+1.)-lgamma(n-k+1.);
    }
    static double biPmf(int n,int k,double p){
        if(n<0||k<0||k>n||p<0||p>1)return 0;
        if(p==0) return k==0?1:0;
        if(p==1) return k==n?1:0;
        return exp(lC(n,k)+k*log(p)+(n-k)*log(1-p));
    }
    static double gPmf(int k,double p){ return(k<1||p<=0||p>1)?0:pow(1-p,k-1)*p; }
    static double dUPmf(int k,int a,int b){ if(a>b)swap(a,b); return(k<a||k>b)?0:1.0/(b-a+1.); }
    static double hgPmf(int N,int K,int n,int k){
        if(N<=0||K<0||n<0||K>N||n>N)return 0;
        if(k<0||k>K||k>n)return 0;
        int f=N-K; if(n-k>f)return 0;
        return exp(lC(K,k)+lC(f,n-k)-lC(N,n));
    }
    static vector<double> normP(const vector<double>& p,size_t s){
        vector<double> v; for(size_t i=s;i<p.size();i++)v.push_back(max(0.,p[i]));
        if(v.empty())return v;
        double sum=0; for(double x:v)sum+=x;
        if(sum<=0){double u=1./v.size();for(double&x:v)x=u;return v;}
        for(double&x:v) x/=sum;
        return v;
    }

    static double distVal(int id,const vector<double>& p,int r,int c){
        double x=(c+0.5)*CELL,y=(r+0.5)*CELL,rad=sqrt(x*x+y*y);
        if(id==1){double m=p.size()>=1?p[0]:0,s=p.size()>=2?p[1]:1;return nPdf(rad,m,s);}
        if(id==2){double l=p.size()>=1?p[0]:1;int k=(int)lround(rad/CELL);return pPmf(k,l);}
        if(id==3){double l=p.size()>=1?p[0]:1;return ePdf(rad,l);}
        if(id==4){double pr=p.size()>=1?p[0]:0.5;int k=((int)floor(rad/CELL)+r+c)%2;return bePmf(k,pr);}
        if(id==5){int n=p.size()>=1?max(0,(int)lround(p[0])):10;double pr=p.size()>=2?p[1]:0.5;
                  int k=(int)lround(rad/CELL);if(n>0)k%=(n+1);return biPmf(n,k,pr);}
        if(id==6){double pr=p.size()>=1?p[0]:0.5;int k=(int)lround(rad/CELL)+1;return gPmf(k,pr);}
        if(id==7){int a=p.size()>=1?(int)lround(p[0]):0,b=p.size()>=2?(int)lround(p[1]):9;
                  int k=(int)lround(rad/CELL);return dUPmf(k,a,b);}
        if(id==8){int N=p.size()>=1?max(1,(int)lround(p[0])):20;
                  int K=p.size()>=2?max(0,(int)lround(p[1])):7;
                  int n=p.size()>=3?max(0,(int)lround(p[2])):5;
                  int k=(int)lround(rad/CELL);if(n>0)k%=(n+1);return hgPmf(N,K,n,k);}
        return 0;
    }

    vector<int> buildStream(int n,const string& raw){
        vector<int> sh(n,0); if(n<=0) return sh;
        auto specs=parseKey(raw); if(specs.empty()) return sh;
        int cols=(int)ceil(sqrt((double)n));
        // rows used implicitly via idx/cols in distVal
        vector<double> comb(n,0); int used=0;
        for(auto& spec:specs){
            vector<double> rv(n);
            double mn=1e300,mx=-1e300;
            for(int i=0;i<n;i++){
                int r=i/cols,c=i%cols;
                double v=distVal(spec.id,spec.p,r,c);
                rv[i]=v; if(v<mn)mn=v; if(v>mx)mx=v;
            }
            double rng=mx-mn;
            for(int i=0;i<n;i++) comb[i]+=(rng>1e-12?(rv[i]-mn)/rng:0);
            used++;
        }
        for(int i=0;i<n;i++){
            int s=(int)lround(comb[i]/used*1000.)%26;
            if(s<0) s+=26;
            sh[i]=s;
        }
        return sh;
    }

    char shiftC(char c,int sh){
        if(!isalpha((unsigned char)c))return c;
        int base=islower((unsigned char)c)?'a':'A';
        return (char)(base+(c-base+sh+26)%26);
    }

    string encrypt(const string& pt,const string& key){
        int n=pt.size(); auto sh=buildStream(n,key);
        string ct=pt; for(int i=0;i<n;i++) ct[i]=shiftC(pt[i],sh[i]);
        return ct;
    }
    string decrypt(const string& ct,const string& key){
        int n=ct.size(); auto sh=buildStream(n,key);
        string pt=ct; for(int i=0;i<n;i++) pt[i]=shiftC(ct[i],-sh[i]);
        return pt;
    }

    string decryptWithShifts(const string& ct,const vector<int>& sh){
        string pt=ct;
        for(int i=0;i<(int)ct.size()&&i<(int)sh.size();i++){
            unsigned char c=(unsigned char)ct[i];
            if(isalpha(c)){int b=islower(c)?'a':'A';pt[i]=(char)(b+(c-b-sh[i]+26)%26);}
        }
        return pt;
    }
}

// ============================================================================
// ATTACK RESULT
// ============================================================================
struct AR {
    bool exact;
    double sim;      // similarity ratio
    double fitness;
    long long ms;
    string bestPt;
    string recovKey;
    string log;      // detailed output captured in stringstream
};

// ============================================================================
// CYLINDRICAL ATTACKS
// ============================================================================
namespace cylAtk {
    using namespace cyl; using namespace util;

    // Attack 1: Known Plaintext — recover key from PT+CT
    AR kpa(const string& ct, const string& pt_orig, const vector<int>& trueKey){
        ostringstream o;
        auto t0=clk::now();
        int cLen=ct.size();
        bool found=false; vector<int> recov;

        for(int rows=1;rows<=cLen&&!found;rows++){
            if(cLen%rows) continue;
            int circ=cLen/rows;
            string padded=pt_orig;
            while((int)padded.size()<cLen) padded+=' ';
            if((int)padded.size()!=cLen) continue;
            vector<string> ptRows(rows,string(circ,' '));
            for(int i=0;i<rows;i++) for(int j=0;j<circ;j++) ptRows[i][j]=padded[i*circ+j];
            auto cs=partial(ct,rows);
            vector<int> shifts(rows,-1); bool ok=true;
            for(int i=0;i<rows&&ok;i++){
                bool sf=false;
                for(int s=0;s<circ&&!sf;s++){
                    string test=cs[i]; rotateStr(test,normShift(-s,circ));
                    if(test==ptRows[i]){shifts[i]=s;sf=true;}
                }
                if(!sf) ok=false;
            }
            if(ok){ found=true; recov.push_back(rows); for(int s:shifts) recov.push_back(s); }
        }

        long long ms=chrono::duration_cast<chrono::milliseconds>(clk::now()-t0).count();
        string recStr=found?keyStr(recov):"NOT FOUND";
        o<<"  KPA result  : "<<recStr<<"\n";
        o<<"  True key    : "<<keyStr(trueKey)<<"\n";
        bool exact=found&&(recov==trueKey);
        o<<"  Match       : "<<(exact?"EXACT":"FAIL")<<"\n";
        double fit=found?scoring::evaluateFitness(pt_orig):-9999;
        return {exact, exact?1.0:0.0, fit, ms, pt_orig, recStr, o.str()};
    }

    // Attack 2: Frequency Analysis (greedy per-row quadgram)
    AR freq(const string& ct, const string& pt_orig, const vector<int>& trueKey){
        ostringstream o;
        auto t0=clk::now();
        int cLen=ct.size();
        double bestSc=-1e18; int bestRows=-1;
        vector<int> bestSh; string bestDec;

        for(int rows=1;rows<=min(cLen,8);rows++){
            if(cLen%rows) continue;
            int circ=cLen/rows;
            auto cs=partial(ct,rows);
            vector<int> shifts(rows,0); double total=0;
            for(int i=0;i<rows;i++){
                double rowBest=-1e18; int bS=0;
                for(int s=0;s<circ;s++){
                    string test=cs[i]; rotateStr(test,(circ-s)%circ);
                    double sc=scoring::evaluateFitness(test);
                    if(sc>rowBest){rowBest=sc;bS=s;}
                }
                shifts[i]=bS; total+=rowBest;
            }
            double avg=total/rows;
            if(avg>bestSc){
                bestSc=avg; bestRows=rows; bestSh=shifts;
                bestDec=applyShifts(cs,rows,circ,shifts);
            }
        }

        long long ms=chrono::duration_cast<chrono::milliseconds>(clk::now()-t0).count();
        vector<int> guessKey; guessKey.push_back(bestRows);
        for(int s:bestSh) guessKey.push_back(s);
        bool exact=(bestDec==pt_orig);
        double sim=similarity(bestDec,pt_orig);
        o<<"  Guess key   : "<<keyStr(guessKey)<<"\n";
        o<<"  Avg fitness : "<<fixed<<setprecision(2)<<bestSc<<"\n";
        o<<"  Recovery    : \""<<bestDec.substr(0,60)<<(bestDec.size()>60?"...\"":"\"")<<"\n";
        double fit=scoring::evaluateFitness(bestDec);
        return {exact,sim,fit,ms,bestDec,keyStr(guessKey),o.str()};
    }

    // Attack 3: Key Exhaustion (brute + heuristic)
    AR brute(const string& ct, const string& pt_orig, const vector<int>& trueKey){
        ostringstream o;
        auto t0=clk::now();
        int cLen=ct.size();
        const int MAX_ROWS=5, MAX_KEYS=100000;

        struct Res{ double sc; int rows; vector<int> sh; string dec;
                    bool operator<(const Res&b)const{return sc>b.sc;}};
        vector<Res> results;

        for(int rows=1;rows<=MAX_ROWS&&rows<=cLen;rows++){
            if(cLen%rows) continue;
            int circ=cLen/rows;
            auto cs=partial(ct,rows);

            // Greedy heuristic per-row
            vector<int> greedySh(rows,0);
            for(int i=0;i<rows;i++){
                double rb=-1e18; int bs=0;
                for(int s=0;s<circ;s++){
                    string test=cs[i]; rotateStr(test,(circ-s)%circ);
                    double sc=scoring::evaluateFitness(test);
                    if(sc>rb){rb=sc;bs=s;}
                }
                greedySh[i]=bs;
            }
            string gdec=applyShifts(cs,rows,circ,greedySh);
            results.push_back({scoring::evaluateFitness(gdec),rows,greedySh,gdec});

            // Full exhaustive if feasible
            long long ks=1;
            for(int i=0;i<rows;i++){
                if(ks>MAX_KEYS/max(circ,1)){ks=MAX_KEYS+1;break;}
                ks*=circ;
            }
            if(ks<=MAX_KEYS){
                vector<int> sh(rows,0);
                function<void(int)> en=[&](int depth){
                    if(depth==rows){
                        string dec=applyShifts(cs,rows,circ,sh);
                        results.push_back({scoring::evaluateFitness(dec),rows,sh,dec});
                        return;
                    }
                    for(int s=0;s<circ;s++){sh[depth]=s;en(depth+1);}
                };
                en(0);
            } else {
                // Random sample
                mt19937 rng(99);
                for(int t=0;t<5000;t++){
                    vector<int> sh(rows); for(int i=0;i<rows;i++) sh[i]=rng()%circ;
                    string dec=applyShifts(cs,rows,circ,sh);
                    results.push_back({scoring::evaluateFitness(dec),rows,sh,dec});
                }
            }
        }

        sort(results.begin(),results.end());
        long long ms=chrono::duration_cast<chrono::milliseconds>(clk::now()-t0).count();

        string bestDec=results.empty()?"":results[0].dec;
        bool exact=(bestDec==pt_orig);
        double sim=similarity(bestDec,pt_orig);
        vector<int> bk; if(!results.empty()){bk.push_back(results[0].rows);for(int s:results[0].sh)bk.push_back(s);}
        o<<"  Best key    : "<<(bk.empty()?"?":keyStr(bk))<<"\n";
        o<<"  Fitness     : "<<fixed<<setprecision(2)<<(results.empty()?-9999:results[0].sc)<<"\n";
        o<<"  Recovery    : \""<<bestDec.substr(0,60)<<(bestDec.size()>60?"...\"":"\"")<<"\n";
        double fit=results.empty()?-9999:results[0].sc;
        return {exact,sim,fit,ms,bestDec,bk.empty()?"?":keyStr(bk),o.str()};
    }
}

// ============================================================================
// SIGNAL ATTACKS
// ============================================================================
namespace sigAtk {
    using namespace sig; using namespace util;

    // Attack 1: KPA — extract shift stream from PT+CT
    AR kpa(const string& ct, const string& pt_orig, const string& trueKey){
        ostringstream o;
        auto t0=clk::now();
        int n=ct.size();
        vector<int> sh(n,0);
        for(int i=0;i<n;i++){
            char p=pt_orig[i], c=ct[i];
            if(isalpha((unsigned char)p)&&isalpha((unsigned char)c))
                sh[i]=(tolower(c)-tolower(p)+26)%26;
        }
        string recovered=decryptWithShifts(ct,sh);
        bool exact=(recovered==pt_orig);
        long long ms=chrono::duration_cast<chrono::milliseconds>(clk::now()-t0).count();
        o<<"  Shift stream (first 20): [";
        for(int i=0;i<min(20,n);i++){if(i)o<<",";o<<sh[i];}
        if(n>20)o<<",...";
        o<<"]\n";
        o<<"  Verification: "<<(exact?"PASS":"FAIL")<<"\n";
        double fit=scoring::evaluateFitness(recovered);
        return {exact,exact?1.0:0.0,fit,ms,recovered,trueKey,o.str()};
    }

    // Attack 2: Frequency Analysis (IC + Kasiski + hill-climbing)
    AR freq(const string& ct, const string& pt_orig, const string& trueKey){
        ostringstream o;
        auto t0=clk::now();
        int n=ct.size();

        double ic=calcIC(ct);
        o<<"  Ciphertext IC : "<<fixed<<setprecision(4)<<ic<<"\n";
        o<<"  IC diagnosis  : "<<(ic<0.045?"polyalphabetic (no period)":ic>0.060?"monoalphabetic":"intermediate")<<"\n";

        // Kasiski: best period
        int bestP=1; double bestPIC=0;
        for(int period=1;period<=min(30,(int)ct.size()/3);period++){
            double avg=0; int cc=0;
            for(int off=0;off<period;off++){
                string col; int ai=0;
                for(unsigned char ch:ct){
                    if(isalpha(ch)){if(ai%period==off)col+=ch;ai++;}
                }
                if((int)col.size()>=2){avg+=calcIC(col);cc++;}
            }
            if(cc>0) avg/=cc;
            if(avg>bestPIC){bestPIC=avg;bestP=period;}
        }
        o<<"  Best period   : "<<bestP<<" (IC="<<fixed<<setprecision(4)<<bestPIC<<")\n";

        // Hill-climbing
        vector<int> sh(n,0);
        {
            double bFit=-1e18; int bs=0;
            for(int s=0;s<26;s++){
                double f=scoring::evaluateFitness(decryptWithShifts(ct,vector<int>(n,s)));
                if(f>bFit){bFit=f;bs=s;}
            }
            fill(sh.begin(),sh.end(),bs);
        }
        double curFit=scoring::evaluateFitness(decryptWithShifts(ct,sh));
        bool improved=true; int passes=0;
        while(improved&&passes<30){
            improved=false;
            for(int i=0;i<n;i++){
                if(!isalpha((unsigned char)ct[i])) continue;
                int orig=sh[i],best=orig; double lb=curFit;
                for(int s=0;s<26;s++){
                    if(s==orig) continue;
                    sh[i]=s;
                    double f=scoring::evaluateFitness(decryptWithShifts(ct,sh));
                    if(f>lb){lb=f;best=s;}
                }
                if(best!=orig){sh[i]=best;curFit=lb;improved=true;}
                else sh[i]=orig;
            }
            passes++;
        }
        string bestDec=decryptWithShifts(ct,sh);
        bool exact=(bestDec==pt_orig);
        double sim=similarity(bestDec,pt_orig);
        long long ms=chrono::duration_cast<chrono::milliseconds>(clk::now()-t0).count();
        o<<"  HC passes     : "<<passes<<" | Fitness: "<<fixed<<setprecision(2)<<curFit<<"\n";
        o<<"  Recovery      : \""<<bestDec.substr(0,60)<<(bestDec.size()>60?"...\"":"\"")<<"\n";
        return {exact,sim,curFit,ms,bestDec,"hill-climb",o.str()};
    }

    // Attack 3: Key Exhaustion using REAL keystream machinery
    AR brute(const string& ct, const string& pt_orig, const string& trueKey){
        ostringstream o;
        auto t0=clk::now();

        // Key dictionary
        vector<string> keys={
            // Dictionary
            "1","2","3","4","6",
            "1(0,1)","1(0,0.5)","1(0,2)","1(1,1)","1(1,2)","1(2,1)","1(2,2)","1(5,2)","1(10,3)",
            "2(0.5)","2(1)","2(2)","2(3)","2(5)","2(10)","2(15)",
            "3(0.5)","3(1)","3(2)","3(3)","3(5)","3(10)",
            "4(0.1)","4(0.2)","4(0.3)","4(0.5)","4(0.7)","4(0.9)",
            "6(0.2)","6(0.3)","6(0.5)","6(0.7)","6(0.8)",
            "5(5,0.3)","5(5,0.5)","5(10,0.5)","7(0,9)","7(0,25)",
            "8(20,7,5)","9(6,0.2,0.3,0.5)","10(0.1,0.2,0.3,0.4)",
            // Combinations
            "1(0,1)02(1)","1(0,1)02(2)","1(1,1)02(3)","1(2,1)03(1)","2(3)01(5,2)",
            "1(0,1)03(2)","2(5)03(1)","4(0.5)01(1,1)","6(0.5)02(2)","1(1,2)04(0.5)",
            // Parameter grid - Normal
            "1(0.5,1)","1(0,1.5)","1(0,3)","1(3,2)","1(5,1)","1(7,2)",
            // Poisson grid
            "2(4)","2(6)","2(7)","2(8)","2(12)","2(20)",
            // Exponential
            "3(0.2)","3(4)","3(7)",
            // Geometric
            "6(0.1)","6(0.4)","6(0.6)","6(0.9)"
        };

        // Random key sampling
        mt19937 rng2(42);
        const int RND=500;
        for(int t=0;t<RND;t++){
            int id=1+(rng2()%3);
            ostringstream ks;
            if(id==1){double m=(rng2()%201-50)*0.1,s=0.1+(rng2()%100)*0.1;ks<<"1("<<m<<","<<s<<")";}
            else if(id==2){double l=0.1+(rng2()%200)*0.1;ks<<"2("<<l<<")";}
            else{double l=0.1+(rng2()%100)*0.1;ks<<"3("<<l<<")";}
            keys.push_back(ks.str());
        }

        struct Cand{string key,plain;double fit;};
        vector<Cand> cands; cands.reserve(keys.size());
        for(auto& k:keys){
            string pt2=decrypt(ct,k);
            cands.push_back({k,pt2,scoring::evaluateFitness(pt2)});
        }
        sort(cands.begin(),cands.end(),[](auto&a,auto&b){return a.fit>b.fit;});

        long long ms=chrono::duration_cast<chrono::milliseconds>(clk::now()-t0).count();
        bool exact=(!cands.empty()&&cands[0].plain==pt_orig);
        bool keyFound=(!cands.empty()&&cands[0].key==trueKey);
        double sim=cands.empty()?0:similarity(cands[0].plain,pt_orig);

        o<<"  Keys tried    : "<<cands.size()<<"\n";
        o<<"  Best key      : "<<(cands.empty()?"?":cands[0].key)<<" (true: "<<trueKey<<")\n";
        o<<"  Key found     : "<<(keyFound?"YES":"NO")<<"\n";
        o<<"  Best fitness  : "<<fixed<<setprecision(2)<<(cands.empty()?-9999:cands[0].fit)<<"\n";
        o<<"  Recovery      : \""<<(cands.empty()?"":cands[0].plain.substr(0,60))
         <<((!cands.empty()&&cands[0].plain.size()>60)?"...\"":"\"")<<"\n";
        return {exact,sim,cands.empty()?-9999:cands[0].fit,ms,
                cands.empty()?"":cands[0].plain,
                cands.empty()?"":cands[0].key,
                o.str()};
    }
}

// ============================================================================
// KEY GENERATION FOR CYLINDRICAL
// ============================================================================
vector<int> makeCylKey(int ptLen, int sizeTier, mt19937& rng){
    // rows chosen so brute-force is testable (≤5), but challenging
    int rows = (sizeTier==0) ? 2+(rng()%2)   // small:  2-3
             : (sizeTier==1) ? 3+(rng()%2)   // medium: 3-4
             :                 4+(rng()%2);  // large:  4-5
    int circ = (ptLen + rows - 1) / rows;
    // circ already determined by encrypt padding — just generate row shifts
    vector<int> key; key.push_back(rows);
    uniform_int_distribution<int> sd(0, max(1,circ)-1);
    for(int i=0;i<rows;i++) key.push_back(sd(rng));
    return key;
}

// Fixed signal keys per tier and index
const string SIG_KEYS[3][10]={
    // SMALL — keys that appear in Attack3's dictionary (recovery expected)
    {"1(0,1)","2(2)","3(1)","4(0.5)","6(0.5)","2(5)","3(2)","4(0.3)","1(1,1)","6(0.7)"},
    // MEDIUM — some in dictionary, some combos
    {"1(1,2)","2(5)","3(2)","1(0,1)02(2)","7(0,9)","1(2,1)","2(3)","4(0.5)","6(0.3)","5(10,0.5)"},
    // LARGE — harder combinations
    {"1(2,3)","2(10)","3(5)","1(0,1)02(2)","8(20,7,5)","1(5,2)","2(15)","3(3)","6(0.5)","4(0.7)"}
};

// ============================================================================
// MAIN TEST HARNESS
// ============================================================================
int main(){
    Logger log("cryptanalysis_log.txt");
    mt19937 rng(42); // fixed seed for reproducibility

    const string SIZES[3]={"Small (20-50)","Medium (80-150)","Large (300-550)"};
    const int MINL[3]={20,80,300}, MAXL[3]={50,150,550};
    const string ATTACKS[3]={"KPA","Frequency Analysis","Key Exhaustion"};
    const string CIPHERS[2]={"Cylindrical Transposition","Signal Substitution"};

    // Summary table rows
    struct Row{ string cipher,size,attack; int testNo; bool exact; double sim,fit; long long ms; };
    vector<Row> summary;
    int globalTest=0;

    for(int cipher=0;cipher<2;cipher++){
        log.sep('='); log.wl("  CIPHER: " + CIPHERS[cipher]); log.sep('=');

        for(int tier=0;tier<3;tier++){
            log.sep('-');
            log.wl("  SIZE TIER: " + SIZES[tier]);
            log.sep('-');

            for(int inp=0;inp<10;inp++){
                globalTest++;
                string pt=textgen::make(MINL[tier],MAXL[tier],rng);

                // --- per-attack block ---
                for(int atk=0;atk<3;atk++){
                    log.sep('=');
                    ostringstream hdr;
                    hdr<<"  TEST #"<<setw(3)<<setfill('0')<<globalTest*3+atk-2<<setfill(' ')
                       <<" | "<<CIPHERS[cipher]<<" | "<<ATTACKS[atk]<<" | "<<SIZES[tier];
                    log.wl(hdr.str());
                    log.sep('-');
                    log.wl("  INPUT #    : " + to_string(inp+1) + " / 10");
                    log.wl("  PLAINTEXT  : \"" + pt.substr(0,70)+(pt.size()>70?"...":"")+"\""
                           + "  ["+to_string(pt.size())+" chars]");

                    AR r;
                    if(cipher==0){
                        // Cylindrical
                        vector<int> key=makeCylKey((int)pt.size(),tier,rng);
                        string ct=cyl::encrypt(pt,key);
                        log.wl("  KEY        : " + cyl::keyStr(key));
                        log.wl("  CIPHERTEXT : \"" + ct.substr(0,70)+(ct.size()>70?"...":"")+"\""
                               + "  ["+to_string(ct.size())+" chars]");
                        log.sep('-');
                        log.wl("  [ATTACK OUTPUT]");
                        if(atk==0) r=cylAtk::kpa(ct,pt,key);
                        else if(atk==1) r=cylAtk::freq(ct,pt,key);
                        else       r=cylAtk::brute(ct,pt,key);
                    } else {
                        // Signal
                        string key=SIG_KEYS[tier][inp];
                        string ct=sig::encrypt(pt,key);
                        log.wl("  KEY        : " + key);
                        log.wl("  CIPHERTEXT : \"" + ct.substr(0,70)+(ct.size()>70?"...":"")+"\""
                               + "  ["+to_string(ct.size())+" chars]");
                        log.sep('-');
                        log.wl("  [ATTACK OUTPUT]");
                        if(atk==0) r=sigAtk::kpa(ct,pt,key);
                        else if(atk==1) r=sigAtk::freq(ct,pt,key);
                        else       r=sigAtk::brute(ct,pt,key);
                    }

                    log.w(r.log);
                    log.sep('-');
                    ostringstream foot;
                    foot<<"  RESULT: "<<(r.exact?"EXACT RECOVERY ✓":"PARTIAL / FAIL  ✗")
                        <<"  |  Similarity: "<<fixed<<setprecision(1)<<r.sim*100<<"%"
                        <<"  |  Fitness: "<<setprecision(2)<<r.fitness
                        <<"  |  Time: "<<r.ms<<"ms";
                    log.wl(foot.str());
                    log.sep('='); log.wl();

                    summary.push_back({CIPHERS[cipher],SIZES[tier],ATTACKS[atk],
                                       globalTest*3+atk-2,r.exact,r.sim,r.fitness,r.ms});
                }
            }
        }
    }

    // ── Final Summary Table ──────────────────────────────────────────────
    log.sep('#');
    log.wl("  FINAL SUMMARY TABLE");
    log.sep('#');
    log.wl(string(120,'-'));
    log.w(  " #   | Cipher                    | Size            | Attack             "
            "| Exact |  Sim%  | Fitness  | Time(ms)\n");
    log.wl(string(120,'-'));

    int totalExact=0;
    for(auto& r:summary){
        if(r.exact) totalExact++;
        ostringstream row;
        row<<setw(4)<<r.testNo<<"| "
           <<left<<setw(27)<<r.cipher<<"| "<<setw(17)<<r.size<<"| "
           <<setw(20)<<r.attack<<"| "
           <<right<<setw(5)<<(r.exact?"YES":"NO")<<" | "
           <<setw(5)<<fixed<<setprecision(1)<<r.sim*100<<" | "
           <<setw(8)<<setprecision(2)<<r.fit<<" | "
           <<setw(7)<<r.ms;
        log.wl(row.str());
    }

    log.wl(string(120,'-'));
    ostringstream tot;
    tot<<"  Total tests: "<<summary.size()
       <<"  |  Exact recoveries: "<<totalExact
       <<" ("<<fixed<<setprecision(1)<<100.*totalExact/summary.size()<<"%)";
    log.wl(tot.str());
    log.sep('#');
    log.wl("\n  Log saved to: cryptanalysis_log.txt");

    return 0;
}
