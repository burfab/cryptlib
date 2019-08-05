#ifndef HASHALGORITHM_H
#define HASHALGORITHM_H

namespace cryptlib {

class HashAlgorithm {
public:
  virtual void transformBlock(const uint8_t *const begin,
                              const uint8_t *const end) = 0;
  virtual void transformBytes(const uint8_t *const p0,
                              const size_t &length) = 0;
  virtual void transformByte(const uint8_t &byte) = 0;

  virtual void init() = 0;

  virtual size_t getHashSizeBits() = 0;
  virtual void getHash(uint8_t *const hash) = 0;

protected:
  inline static uint32_t LeftRotate(const uint32_t &n, const size_t &s) {
    return (n << s) ^ (n >> (sizeof(n) * 8 - s));
  }
};
#endif // !HASHALGORITHM_H
}