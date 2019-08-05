#include <iostream>
#include "../header/sha1_algorithm.hpp"

using namespace cryptlib;

void hash(HashAlgorithm &alg, const char* trans){
    alg.transformBytes((uint8_t*)trans, strlen(trans));
    uint8_t digest[20];
    alg.getHash(digest);

    std::cout << "HASH: " << std::endl << "0x";
    for(size_t i = 0; i < alg.getHashSizeBits() / 8; i++){
        std::cout << std::hex << (uint32_t)digest[i];
    }
    std::cout << std::endl;
}

int main() { 
    Sha1Algorithm alg = Sha1Algorithm();
    alg.init();
    const char* trans = "qwertyuiop[]asdfghjkl;'zxcvbnm,./?><~qwertyuiop[]asdfghjaa";
    hash(alg, trans);
    return 1;
}
