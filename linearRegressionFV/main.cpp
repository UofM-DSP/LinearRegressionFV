/**
 *
 * This file is part of FV-NFLlib
 *
 * Copyright (C) 2016  CryptoExperts
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cstddef>
#include <gmp.h>
#include <gmpxx.h>
#include <nfl.hpp>
#include "lib/params/params.cpp"

#include "lib/prng/fastrandombytes.cpp"
#include "lib/prng/randombytes.cpp"

#include "fvnamespace.h"
//#include "nfl/prng/crypto_stream_salsa20.h"

#include "FV.hpp"

using namespace std;
using namespace FV;

void loadData(string fileName, int numberOfAttributes, int numberOfRows, int **plainTextData, int *classData) {
    ifstream inputFileStream(fileName);

    string inputLine;
    string token;
    int numberOfRowsEntered = 0;

    int min = 9999999;
    int max = -999999;


    if (inputFileStream.is_open()) {
        //attr line
        getline(inputFileStream, inputLine);

        while (!inputFileStream.eof() && getline(inputFileStream, inputLine)) {

//            cout << inputLine + "\n";
            istringstream stringStream(inputLine);
            //omit serial attr
            getline(stringStream, token, ',');

            for (int j = 0; j < numberOfAttributes && getline(stringStream, token, ',') && numberOfRowsEntered < numberOfRows; j++) {
                plainTextData[numberOfRowsEntered][j] = stoi(token);
                min = plainTextData[numberOfRowsEntered][j] < min ? plainTextData[numberOfRowsEntered][j] : min;
                max = plainTextData[numberOfRowsEntered][j] > max ? plainTextData[numberOfRowsEntered][j] : max;
//                    cout << plainTextData[numberOfRowsEntered][j] << endl;
            }
            //get class data
            getline(stringStream, token, ',');
            classData[numberOfRowsEntered] = stoi(token);
//            cout << classData[numberOfRowsEntered] <<endl;
            numberOfRowsEntered++;

        }

    } else {
        cout << "File opening error";
    }

    inputFileStream.close();

//    cout << "Min is " << min << endl;
//    cout << "Max is " << max << endl;
}



void saveSecretKey(const char* filename, sk_t &sk){
    ofstream myfile;
    myfile.open (filename);
    sk.value.serialize_manually(myfile);
    /*std::array <mpz_t, DEGREE> tmp =  sk.value.poly2mpz();
    for (int i = 0; i < DEGREE; ++i) {
        myfile<<tmp[i]<<((i<DEGREE-1)?",":"");
    }
    myfile<<"\n";*/
    myfile.close();

}

void savePublicKey(const char* filename, pk_t &pk){
    ofstream myfile;
    myfile.open (filename);
    pk.a.serialize_manually(myfile);
    pk.b.serialize_manually(myfile);
    /*std::array <mpz_t, DEGREE> tmp =  pk.a.poly2mpz();
    for (int i = 0; i < DEGREE; ++i) {
        myfile<<tmp[i]<<((i<DEGREE-1)?",":"");
    }*/
    //myfile<<"\n";

    /*tmp =  pk.b.poly2mpz();
    for (int i = 0; i < DEGREE; ++i) {
        myfile<<tmp[i]<<((i<DEGREE-1)?",":"");
    }
    myfile<<"";*/

    myfile.close();

}

void saveEvalKey(const char* filename, evk_t &evk){
    ofstream myfile;
    myfile.open (filename);

    for (unsigned j = 0; j < evk.ell; ++j) {
        evk.values[j][0].serialize_manually(myfile);
        evk.values[j][1].serialize_manually(myfile);
        /*std::array<mpz_t, DEGREE> tmp = evk.values[j][0].poly2mpz();
        for (int i = 0; i < DEGREE; ++i) {
            myfile << tmp[i] << ((i < DEGREE - 1) ? "," : "");
        }
        myfile << "\n";
        tmp = evk.values[j][1].poly2mpz();
        for (int i = 0; i < DEGREE; ++i) {
            myfile << tmp[i] << ((i < DEGREE - 1) ? "," : "");
        }
        myfile << "\n";*/

    }

    //myfile << pk->b_shoup<<"\n";
    /*tmp =  pk.delta.poly2mpz();
    for (int i = 0; i < DEGREE; ++i) {
        myfile<<tmp[i]<<((i<DEGREE-1)?",":"");
    }
    myfile<<"\n";*/
    //myfile << pk->delta_shoup<<"\n";
    myfile.close();

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

    sk_t sk;
    string secret_key_file = "secret.key";
    saveSecretKey(secret_key_file.c_str(),sk);
    string eval_key_file = "eval.key";

    int word_size = 1 << 6;
    evk_t evk(sk, word_size);
    saveEvalKey(eval_key_file.c_str(),evk);

    pk_t pk(sk, evk);
    string public_key_file = "public.key";
    savePublicKey(public_key_file.c_str(),pk);
    //readPublicKey(pk);

    int numberOfAttributes = 22, numberOfRows = 195; //22 attr and one class data
    int **plainTextData;
    int *classData;
    string fileName = "modifiedIntRemovedoneParkinsons.data";



    mess_t m(mpz_class("-99999999"));//do not use encrypt_integer for now, need to check its function
    //also this is the usual way to encrypt, make a mess_t of a number then encrypt, Best.
    ciphertext_t minusVal;
    FV::encrypt(minusVal, pk, m);




    //init data
    plainTextData = new int *[numberOfRows];
    classData = new int[numberOfRows];

    for (int i = 0; i < numberOfRows; i++) {
        plainTextData[i] = new int[numberOfAttributes];
    }

    loadData(fileName, numberOfAttributes, numberOfRows, plainTextData, classData);






    ofstream labelsEncrypted, dataEncrypted;
    labelsEncrypted.open("classData.encrypted");
    dataEncrypted.open("attributes.encrypted");


    // n -> number of rows
    // m-1 -> number of attributes

    ciphertext_t cipherTextDataPoly[numberOfRows][numberOfAttributes];
    ciphertext_t classDataPoly[numberOfRows];
    //poly_t rawDataPolyT[n][m - 1];
    for (unsigned i = 0; i < numberOfRows; i++) {
        for (unsigned j = 0; j < numberOfAttributes; j++) {

            //std::cout << rawData[y][x];

//            FV::encrypt_integer(cipherTextDataPoly[i][j], pk, plainTextData[i][j]);
            mess_t tempMpz(mpz_class(plainTextData[i][j]));
            FV::encrypt(cipherTextDataPoly[i][j], pk, tempMpz);


            cipherTextDataPoly[i][j].c0.serialize_manually(dataEncrypted);
            cipherTextDataPoly[i][j].c1.serialize_manually(dataEncrypted);

        }

//        FV::encrypt_integer(classDataPoly[i], pk, classData[i]);
        mess_t tempMpz(mpz_class(classData[i]));
        FV::encrypt(classDataPoly[i], pk, tempMpz);

        classDataPoly[i].c0.serialize_manually(labelsEncrypted);
        classDataPoly[i].c1.serialize_manually(labelsEncrypted);

    }
//    std::cout << "log2(q)=" << classDataPoly[0].c0.bits_in_moduli_product() << std::endl;
//    std::cout << "degree=" << classDataPoly[0].c0.degree << std::endl;
//    std::cout << "q=" << classDataPoly[0].c0.moduli_product() << std::endl;
    labelsEncrypted.close();
    dataEncrypted.close();

//    cout << "Decrypting records" << endl;

//    for (unsigned y = 0; y < numberOfRows; y++) {
//        for (unsigned x = 0; x <numberOfAttributes; x++) {
//            printEncValPrint(cipherTextDataPoly[y][x], sk, pk);
//            cout << " ";
//        }
//        printEncValPrint(classDataPoly[y ], sk, pk);
//        cout << endl;
//    }
//    cout << "Encryption done" << endl;


    return 0;
}