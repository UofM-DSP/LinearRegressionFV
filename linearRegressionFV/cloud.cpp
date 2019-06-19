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
#include <omp.h>

#include "lib/prng/fastrandombytes.cpp"
#include "lib/prng/randombytes.cpp"
//fe016@ucsd.edu

#include "FV.hpp"

using namespace std;
using namespace FV;
const int CPU = 4;


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
    cout << evk.ell << endl;
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
    int numberOfAttributes = 22, numberOfRows = 10; //22 attr and one class data

    sk_t sk;
    readSecretKey(sk);

    evk_t evk(1 << 6);
    readEvalKey(evk);

    pk_t pk1;
    readPublicKey(pk1);
    //pk.evk=&evk;
    pk_t pk = pk_t(pk1.a, pk1.a_shoup, pk1.b, pk1.b_shoup, evk);
//    std::cout << "Read all the keys" << std::endl;

    ifstream classDataStream("classData.encrypted");
    ifstream attributesStream("attributes.encrypted");

    int numberOfTrainingData = 10, numberOfIteration = 1;

    //get encrypted data
    if (classDataStream.is_open() && attributesStream.is_open()) {

        ciphertext_t attributesPolyEncrypted[numberOfRows][numberOfAttributes];
        ciphertext_t classDataPolyEncrypted[numberOfRows];

        for (unsigned y = 0; y < numberOfRows; y++) {
            for (unsigned x = 0; x < numberOfAttributes; x++) {
                attributesPolyEncrypted[y][x].c0.deserialize_manually(attributesStream);
                attributesPolyEncrypted[y][x].c1.deserialize_manually(attributesStream);
                attributesPolyEncrypted[y][x].isnull = false;
                attributesPolyEncrypted[y][x].pk = &pk;
//                printEncValPrint(attributesPolyEncrypted[y][x], sk, pk);
//                cout << ", ";
            }
            classDataPolyEncrypted[y].c0.deserialize_manually(classDataStream);
            classDataPolyEncrypted[y].c1.deserialize_manually(classDataStream);
            classDataPolyEncrypted[y].isnull = false;
            classDataPolyEncrypted[y].pk = &pk;
//            printEncValPrint(classDataPolyEncrypted[y], sk, pk);
//            cout << endl;
        }
//        cout << "Data file read complete" << endl;



        //linear regression start
        //declaration
        int totalNumberOfAttributes = numberOfAttributes;
        int numberOfIteration = 1;
        ciphertext_t weightVector[totalNumberOfAttributes], newWeightVector[totalNumberOfAttributes];
        ciphertext_t outputEquationValue, multiplyingFactor, tempSum, cipherLearningRate, cipherOfZero, numberOfTrainingCipher;



        //initialization of constant valued ciphertext
        mess_t minusOneMPZ(mpz_class("-1"));
        mess_t zeroMPZ(mpz_class("0"));
        mess_t learningFactorReciprocalMPZ(mpz_class("10"));
        mess_t numberOfTrainingMPZ(numberOfTrainingData);

        FV::encrypt(multiplyingFactor, pk, minusOneMPZ);
        FV::encrypt(cipherLearningRate, pk, learningFactorReciprocalMPZ);
        FV::encrypt(numberOfTrainingCipher, pk, numberOfTrainingMPZ);

        for (int i = 0; i < totalNumberOfAttributes; ++i) {
            FV::encrypt(weightVector[i], pk, zeroMPZ);
            FV::encrypt(newWeightVector[i], pk, zeroMPZ);
        }
        //decrypt weights
//        for (int j = 0; j < totalNumberOfAttributes; ++j) {
//            printEncValPrint(weightVector[j], sk, pk);
//            cout << " ";
//        }
        ciphertext_t zero;
        FV::encrypt(zero, pk, zeroMPZ);

        {
            for (int iteration = 0; iteration < numberOfIteration; ++iteration) {

                for (int attributeIndex = 0; attributeIndex < totalNumberOfAttributes; ++attributeIndex) {
                    tempSum = zero;
                    //FV::encrypt(tempSum, pk, zeroMPZ);
                    //                cout << "\n----------Starting for attr #" << attributeIndex <<"--------";
                    //                cout << "TempSum at starting: ";
                    //                printEncValPrint(tempSum, sk, pk);
                    //                cout << endl;
                    ciphertext_t tempSumArr[numberOfTrainingData];

                    for (int j = 0; j < numberOfTrainingData; ++j) {
                        tempSumArr[j] = zero;
                    }

#pragma omp parallel num_threads(CPU)
                    {
#pragma omp parallel for
                        for (int recordIndex = 0; recordIndex < numberOfTrainingData; recordIndex++) {
                            //mat mul
                            outputEquationValue = zero;
                            //FV::encrypt(outputEquationValue, pk, zeroMPZ);
                            //attributeValue = attributesPolyEncrypted[recordIndex][attributeIndex];
                            if (iteration > 0) {
                                for (int i = 0; i < totalNumberOfAttributes; ++i) {
                                    outputEquationValue += (attributesPolyEncrypted[recordIndex][i] * weightVector[i]);
                                }
                            }
                            //                    cout << iteration << " " << attributeIndex << " " << recordIndex << " " << endl;
                            //                    cout << "\noutput eqn val:";
                            //                    printEncValPrint(outputEquationValue, sk, pk);
                            //                    cout << "\nmultiplying factor:";
                            //                    printEncValPrint(multiplyingFactor, sk, pk);
                            //                    cout << endl;
                            //                    cout << "\ngiven class data:";
                            //                    printEncValPrint(classDataPolyEncrypted[recordIndex], sk, pk);
                            //                    cout << "\nattr val:";
                            //                    printEncValPrint(attributeValue, sk, pk);
                            //
                            ciphertext_t tmp = ((outputEquationValue - classDataPolyEncrypted[recordIndex]) *
                                                attributesPolyEncrypted[recordIndex][attributeIndex]);
#pragma omp critical
                            tempSumArr[recordIndex]=tmp;
                            //                    cout << "\noutput eqn val:";
                            //                    printEncValPrint(outputEquationValue, sk, pk);
                        }
                    }

                    //                newWeightVector[attributeIndex] = weightVectosr[attributeIndex] + tempSum;

                    for (int k = 0; k < numberOfTrainingData; ++k) {
                        tempSum += tempSumArr[k];
                    }
                    newWeightVector[attributeIndex] =
                            (weightVector[attributeIndex] * 10 * numberOfTrainingData) - tempSum;
                    cout << "weight vector " << attributeIndex << " ";
                    printEncValPrint(newWeightVector[attributeIndex], sk, pk);
                    cout << endl;
                    //}

                }

                //set new weight vector and reinitialize
                //#pragma omp parallel for
                for (int j = 0; j < totalNumberOfAttributes; ++j) {
                    weightVector[j] = newWeightVector[j];
                    newWeightVector[j] = zero;//FV::encrypt(newWeightVector[j], pk, zeroMPZ);
                }
            }
        }



        //write final vector in file
        ofstream writeWeightEncrypted;
        writeWeightEncrypted.open("weights.encrypted");
        cout << "writing weights";
        for (unsigned i = 0; i < totalNumberOfAttributes; i++) {
            weightVector[i].c0.serialize_manually(writeWeightEncrypted);
            weightVector[i].c1.serialize_manually(writeWeightEncrypted);
        }
        writeWeightEncrypted.close();
        cout << "writing weights done";
//
//        //reading weights
//        ifstream readWeightEncrypted("classData.encrypted");
//        if ( readWeightEncrypted.is_open() ) {
//            for (int i = 0; i < totalNumberOfAttributes; ++i) {
//                weightVector[i].c0.deserialize_manually(classDataStream);
//                weightVector[i].c1.deserialize_manually(classDataStream);
//                weightVector[i].isnull = false;
//                weightVector[i].pk = &pk;
//            }
//        }
//

    } else {
        cout << "Could not open file. Exiting" << endl;
    }


    return 0;
}