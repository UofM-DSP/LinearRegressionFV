//
// Created by tlangminung on 16/10/17.
//

#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <iterator>
#include <vector>
#include <vector>
#include <algorithm>
#include <sstream>
#include <cstddef>
#include <gmp.h>
#include <gmpxx.h>
#include <math.h>
#include <omp.h>
#include <nfl.hpp>
#include "fvnamespace.h"
#include "lib/params/params.cpp"

#include "lib/prng/fastrandombytes.cpp"
#include "lib/prng/randombytes.cpp"

//const int DEGREE = 1 << 12;
//namespace FV {
//    namespace params {
//        using poly_t = nfl::poly_from_modulus<uint64_t, DEGREE, 62*4>;
//        template<typename T>
//        struct plaintextModulus;
//
//        template<>
//        struct plaintextModulus<mpz_class> {
//            static mpz_class value() { return mpz_class("1234567239"); }
//        };
//
//        using gauss_struct = nfl::gaussian<uint16_t, uint64_t, 2>;
//        using gauss_t = nfl::FastGaussianNoise<uint16_t, uint64_t, 2>;
//        gauss_t fg_prng_sk(3.0, 128, 1 << 14);
//        gauss_t fg_prng_evk(3.0, 128, 1 << 14);
//        gauss_t fg_prng_pk(3.0, 128, 1 << 14);
//        gauss_t fg_prng_enc(3.0, 128, 1 << 14);
//    }
//}  // namespace FV::params
#include "FV.hpp"

using namespace std;
using namespace FV;


void readPublicKey(pk_t &pk) {
    string line;
    ifstream myfile("public.key");
    if (myfile.is_open()) {
        pk.a.deserialize_manually(myfile);
        pk.a_shoup = nfl::compute_shoup(pk.a);
        pk.b.deserialize_manually(myfile);
        pk.b_shoup = nfl::compute_shoup(pk.b);
        /*
        int lineno=0;
        while ( getline (myfile,line) )
        {
            //unsigned long long int *res=get_array(line);
            if (!line.empty()) {
                switch(lineno){
                    case 0:pk.a = get_array(line);break;
                    case 1: pk.b = get_array(line);pk.b_shoup = nfl::compute_shoup(pk.b);break;
                    //case 2: pk.delta =get_array(line);pk.delta_shoup = nfl::compute_shoup(pk.delta);break;
                }
                lineno++;
            }
        }*/
        myfile.close();
    } else cout << "Unable to open file";
}

void readSecretKey(sk_t &sk) {
    string line;
    ifstream myfile("secret.key");
    if (myfile.is_open()) {
        sk.value.deserialize_manually(myfile);
        sk.value_shoup = nfl::compute_shoup(sk.value);
        /*int lineno=0;
        while ( getline (myfile,line) ) {
            //unsigned long long int *res=get_array(line);
            if (!line.empty()) {
                sk.value = get_array(line);
                sk.value_shoup = nfl::compute_shoup(sk.value);

                lineno++;
                break;
            }
        }*/

        myfile.close();
    } else cout << "Unable to open file";
}

void readEvalKey(evk_t &evk) {
    string line;
    ifstream myevalfile("eval.key");

    /*int ell = floor(mpz_sizeinbase(P::moduli_product(), 2) / word_size) + 1;
    const int N = ell;
    std::array <P,  N> arr;*/
    //cout << evk.ell << endl;
    if (myevalfile.is_open()) {
        for (unsigned j = 0; j < evk.ell; ++j) {
            evk.values[j] = new FV::params::poly_p[2];
            evk.values_shoup[j] = new FV::params::poly_p[2];
            evk.values[j][0].deserialize_manually(myevalfile);
            evk.values_shoup[j][0] = nfl::compute_shoup(evk.values[j][0]);
            evk.values[j][1].deserialize_manually(myevalfile);
            evk.values_shoup[j][1] = nfl::compute_shoup(evk.values[j][1]);
        }
        /*int lineno=0;
        while ( getline (myevalfile,line) ) {
            if (!line.empty()) {

                if(lineno%2==0) {
                    evk.values[lineno / 2] = new FV::params::poly_p[2];evk.values_shoup[lineno/2]= new FV::params::poly_p[2];
                }
                evk.values[lineno/2][lineno%2] = get_array(line);
                evk.values_shoup[lineno/2][lineno%2] = nfl::compute_shoup(evk.values[lineno/2][lineno%2]);
                //cout<<lineno<<endl;

                lineno++;

            }else break;
        }*/

        myevalfile.close();
    } else cout << "Unable to eval open file";
}

void printEncValPrint(ciphertext_t &ct, sk_t &sk, pk_t &pk) {
    mess_t m_dec;

    decrypt(m_dec, sk, pk, ct);
    //std::cout <<m_dec;
    mpz_t tmp;
    FV::params::poly_t pt = (FV::params::poly_t) m_dec.getValue();
    std::array<mpz_t, DEGREE> arr = pt.poly2mpz();
    mpz_t &s = arr[0];
    mpz_init(tmp);
    mpz_cdiv_q_ui(tmp, FV::params::plaintextModulus<mpz_class>::value().get_mpz_t(), 2);
    //std::cout<<tmp<<std::endl;std::cout<<s<<std::endl;
    if (mpz_cmp(s, tmp) > 0) {
        mpz_sub(tmp, FV::params::plaintextModulus<mpz_class>::value().get_mpz_t(), s);
        //mpz_tdiv_q(tmp,tmp,quantization);
        //std::cout << "beta " << i << ": -" <<tmp << std::endl;
        std::cout << "-" << tmp;
    } else {
        //mpz_tdiv_q(tmp,tmp,quantization);
        //std::cout << "beta " << i << ": " << m_dec << std::endl;
        std::cout << m_dec;
    }
    mpz_clear(tmp);

    //return;
}

int main() {
    int numberOfAttributes = 22, numberOfRows = 150; //22 attr and one class data

    sk_t sk;
    readSecretKey(sk);

    evk_t evk(1 << 6);
    readEvalKey(evk);

    pk_t pk1;
    readPublicKey(pk1);
    //pk.evk=&evk;
    pk_t pk = pk_t(pk1.a, pk1.a_shoup, pk1.b, pk1.b_shoup, evk);
//    std::cout << "Read all the keys" << std::endl;


    //reading weights
    int totalNumberOfAttributes = 22;
    ifstream readWeightEncrypted("weights.encrypted");
    ciphertext_t weightVector[totalNumberOfAttributes], newWeightVector[totalNumberOfAttributes];
    if (readWeightEncrypted.is_open()) {
        for (int i = 0; i < totalNumberOfAttributes; ++i) {
            weightVector[i].c0.deserialize_manually(readWeightEncrypted);
            weightVector[i].c1.deserialize_manually(readWeightEncrypted);
            weightVector[i].isnull = false;
            weightVector[i].pk = &pk;
            printEncValPrint(weightVector[i], sk, pk);
            cout << endl;
        }
        readWeightEncrypted.close();
    } else {
        cout << "File read error"<< endl;
    }


    return 0;
}