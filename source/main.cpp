#include <iostream>
#include "../header/sha512_algorithm.hpp"
#include "../header/sha256_algorithm.hpp"
#include "../header/sha1_algorithm.hpp"

using namespace cryptlib;

void hash(HashAlgorithm &alg, const char* trans){
    alg.transformBytes((uint8_t*)trans, strlen(trans));
    size_t hashSizeByte = alg.getHashSizeBits() / 8;
    uint8_t digest[hashSizeByte];
    alg.getHash(digest);

    for(size_t i = 0; i < hashSizeByte; i++){
        std::cout << std::hex << (uint32_t)digest[i];
    }
    std::cout << std::endl;
}

int main() { 
    std::cout << std::endl;
    std::cout << std::endl;

    Sha1Algorithm alg = Sha1Algorithm();
    alg.init();
    const char* trans = "hallo";
    std::cout << "SHA1 HASH: " << std::endl << "0x ";
    hash(alg, trans);
    
    std::cout << std::endl;
    
    Sha512Algorithm alg2 = Sha512Algorithm();
    alg2.init();
    std::cout << "SHA512 HASH: " << std::endl << "0x ";
    hash(alg2, trans);
    
    std::cout << std::endl;
    
    Sha256Algorithm alg3 = Sha256Algorithm();
    alg3.init();
    std::cout << "SHA256 HASH: " << std::endl << "0x ";
    hash(alg3, trans);


    std::cout << std::endl;
    std::cout << std::endl;
    return 1;
}
