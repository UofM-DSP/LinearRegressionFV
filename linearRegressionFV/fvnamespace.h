//
// Created by tlangminung on 21/10/17.
//
#include <gmpxx.h>
#include <nfl.hpp>

#ifndef LINEARREGRESSIONFV_FVNAMESPACE_H
#define LINEARREGRESSIONFV_FVNAMESPACE_H

#endif //LINEARREGRESSIONFV_FVNAMESPACE_H
const int DEGREE = 1 << 12;
namespace FV {
    namespace params {
        using poly_t = nfl::0<uint64_t, DEGREE, 62*2>;
        template<typename T>
        struct plaintextModulus;

        template<>
        struct plaintextModulus<mpz_class> {
            static mpz_class value() { return mpz_class("1234567239"); }
        };

        using gauss_struct = nfl::gaussian<uint16_t, uint64_t, 2>;
        using gauss_t = nfl::FastGaussianNoise<uint16_t, uint64_t, 2>;
        gauss_t fg_prng_sk(3.0, 128, 1 << 14);
        gauss_t fg_prng_evk(3.0, 128, 1 << 14);
        gauss_t fg_prng_pk(3.0, 128, 1 << 14);
        gauss_t fg_prng_enc(3.0, 128, 1 << 14);
    }
}  // namespace FV::params