/*
 *  REFERENCE IMPLEMENTATION OF algorithm2 of the work of Banik et al. on toy STREAM CIPHER GRAIN-v8a
 *
 * Filename: algo2.cpp
 *
 * Author:
 * Hiren Garai
 * Dept. of Mathematics
 * BITS Pilani, Hyderabad Campus
 * Telangana, 500078
 * email: hirengarai@gmail.com
 * updated: 02/08/2023
 *
 * Synopsis:
 *  This file contains functions that implement the Key-IV pair finding algo of Maitra sir's paper for the
 *  toy stream cipher Grain-V8a. It is for research purpose only.
 *
 * running command: g++ algo2.cpp && ./a.out
 */

#include <bitset>
#include <chrono>
#include <cmath> // pow function
#include <ctime> //  time
#include <iostream>

using namespace std;
typedef uint8_t u8;
typedef uint32_t u32;

#define LENGTH 8
#define MOD 256 // pow(2, 32 )

// random number of 8 bits
static inline u8 drandom()
{
    return MOD * drand48();
}

void HexPrintState(u8 *x, int size);
void KLA(u8 key, u8 IV, u8 *nfsr, u8 *lfsr);
void KSA(u8 *nfsr, u8 *lfsr, u8 &f, u8 &g, u8 &h);
void INVKSA(u8 *nfsr, u8 *lfsr, u8 &f, u8 &g, u8 &h);
void PRGA(u8 *nfsr, u8 *lfsr, u8 &f, u8 &g, u8 &h);
void PrintState(u8 *x, int size);
void Update(u8 *nfsr, u8 *lfsr, u8 &f, u8 &g, u8 &h);

int main()
{
    srand48(time(NULL));
    auto start = chrono::high_resolution_clock::now();
    // Your code goes here
    u8 initKeyCopy, initIVCopy, Invkeycopy[8], Invivcopy[8], Nfsr[LENGTH], Lfsr[LENGTH], f, g, h, number, k, iv;
    u8 Invnfsr[LENGTH], Invlfsr[LENGTH], inf, ing, inh;
    u32 invnumber;
    bool flag;
    int shiftcount{0};
    // for (int loop{0}; loop < pow(2, 18); ++loop)
    // {
    // following the logic of Banik et. al we should get a Key-IV pair among 2^2 = 4 trials
    for (int trial{0}; trial < 4; ++trial)
    {
        // for (int kloop{0}; kloop < 256; ++kloop)
        // {
        //     for (int iloop{0}; iloop < 16; ++iloop)
        //     {

        flag = false;
        number = 0;
        invnumber = 0;

        // 8-bit key
        k = drandom();
        // 4-bit IV
        iv = drandom() % 16;

        KLA(k, iv, Nfsr, Lfsr);

        // store purpose
        initKeyCopy = k;
        initIVCopy = iv;

        // 2 times KSA inverse
        for (int i{0}; i < 2; ++i)
        {
            INVKSA(Nfsr, Lfsr, f, g, h);
        }

        for (int i{0}; i < LENGTH; ++i)
        {
            Invkeycopy[i] = Nfsr[i];
            Invivcopy[i] = Lfsr[i];
            Invnfsr[i] = Nfsr[i];
            Invlfsr[i] = Lfsr[i];
        }
        KLA(k, iv, Nfsr, Lfsr);

        // 16 time KSA
        for (int clock{0}; clock < 16; ++clock)
        {
            KSA(Nfsr, Lfsr, f, g, h);
            KSA(Invnfsr, Invlfsr, inf, ing, inh);
        }

        // 2 times PRGA
        int temp{0};
        for (int clock{0}; clock < 2; ++clock)
        {
            PRGA(Invnfsr, Invlfsr, inf, ing, inh);
            if (inh)
            {
                clock = 2;
                invnumber = 0;
            }
            else
            {
                temp++;
                invnumber <<= 1;
                invnumber |= inh;
            }
        }
        if (temp == 2)
        {
            shiftcount++;
            flag = true;
            trial = 4;
        }
        if (flag)
        {
            cout << "####### ####### new shift found ####### #######\n";
            cout << "The init. key is: 0x" << hex << unsigned(initKeyCopy) << "\n";
            cout << "The init. IV is: 0x" << hex << unsigned(initIVCopy) << "\n";

            cout << "*********************************\n";
            cout << "The inv. key is: 0x";
            HexPrintState(Invkeycopy, LENGTH);
            cout << "The corr. IV is: 0x";
            HexPrintState(Invivcopy, LENGTH);

            cout << "The keystream:    ";
            for (int clock{0}; clock < 16; ++clock)
            {
                PRGA(Nfsr, Lfsr, f, g, h);
                cout << unsigned(h);
            }
            cout << "\n";
            cout << "Inv. keystream: ";
            for (int clock{2}; clock < 18; ++clock)
            {
                PRGA(Invnfsr, Invlfsr, inf, ing, inh);
                invnumber <<= 1;
                invnumber |= inh;
            }
            bitset<18> b1(invnumber);
            cout << b1 << "\n";
        }
    }
    // }
    // }
    // }
    auto end = chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << dec << "Execution time: " << duration.count() << " microseconds\n"; // 1 sec = 10^6 micro seconds.
}

void KLA(u8 key, u8 IV, u8 *nfsr, u8 *lfsr)
{
    bitset<LENGTH> temp(key);

    // nfsr state
    for (int i{0}; i < LENGTH; ++i)
    {
        nfsr[i] = temp[LENGTH - 1 - i];
    }

    // lfsr state
    bitset<LENGTH - 4> temp1(IV);
    for (int i{0}; i < (LENGTH - 4); ++i)
    {

        lfsr[i] = temp1[LENGTH - 5 - i];
    }
    lfsr[4] = 0;
    lfsr[5] = 1;
    lfsr[6] = 0;
    lfsr[7] = 1;
}

void PRGA(u8 *nfsr, u8 *lfsr, u8 &f, u8 &g, u8 &h)
{
    Update(nfsr, lfsr, f, g, h);
}

void PrintState(u8 *x, int size)
{
    int counter{0};
    for (int i{0}; i < size; ++i)
    {
        cout << unsigned(x[i]);
        counter++;
        if (!(counter % 4))
        {
            cout << " ";
        }
    }
    printf("\n");
}

void HexPrintState(u8 *x, int size)
{
    int counter{0}, number{0}, temp{0};

    for (int i{0}; i < size; ++i)
    {
        number <<= 1;
        number |= x[i];
    }
    cout << hex << unsigned(number);
    printf("\n");
}

void KSA(u8 *nfsr, u8 *lfsr, u8 &f, u8 &g, u8 &h)
{
    Update(nfsr, lfsr, f, g, h);

    // updatation of the last bit of the nfsr and lfsr with filter function
    nfsr[LENGTH - 1] ^= h;
    lfsr[LENGTH - 1] ^= h;
}

void INVKSA(u8 *nfsr, u8 *lfsr, u8 &f, u8 &g, u8 &h)
{
    u8 l{lfsr[7]}, n{nfsr[7]};
    for (int i{7}; i > 0; i--)
    {
        lfsr[i] = lfsr[i - 1];
        nfsr[i] = nfsr[i - 1];
    }
    h = (nfsr[4] * lfsr[2]) ^ (nfsr[7] * lfsr[6]) ^ nfsr[2] ^ nfsr[4] ^ nfsr[7] ^ lfsr[5];

    lfsr[0] = h ^ l ^ (lfsr[1]) ^ (lfsr[6]) ^ (lfsr[7]);
    nfsr[0] = h ^ n ^ lfsr[0] ^ (nfsr[2]) ^ (nfsr[3]) ^ (nfsr[3] * nfsr[5]) ^ (nfsr[1] * nfsr[2]) ^ (nfsr[4] * nfsr[6]);
}

void Update(u8 *nfsr, u8 *lfsr, u8 &f, u8 &g, u8 &h)
{
    // lfsr part
    u8 loutput = lfsr[0];                              // output bit
    f = (lfsr[0]) ^ (lfsr[1]) ^ (lfsr[6]) ^ (lfsr[7]); // feedback bit

    g = nfsr[0] ^ nfsr[2] ^ nfsr[3] ^ (nfsr[3] * nfsr[5]) ^ (nfsr[1] * nfsr[2]) ^ (nfsr[4] * nfsr[6]); // feedback bit

    // filter function h
    h = ((nfsr[4] * lfsr[2]) ^ (nfsr[7] * lfsr[6])) ^ nfsr[2] ^ nfsr[4] ^ nfsr[7] ^ lfsr[5];

    // shift the nfsr, lfsr
    for (int i{0}; i < LENGTH - 1; ++i)
    {
        nfsr[i] = nfsr[i + 1];
        lfsr[i] = lfsr[i + 1];
    }

    // updatation of the last bit of the nfsr and lfsr
    nfsr[LENGTH - 1] = g ^ loutput;
    lfsr[LENGTH - 1] = f;
}
