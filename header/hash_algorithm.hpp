#ifndef HASHALGORITHM_H
#define HASHALGORITHM_H

namespace cryptlib {

class HashAlgorithm {
public:
  virtual inline void transformBlock(const uint8_t *const begin,
                              const uint8_t *const end) = 0;
  virtual inline void transformBytes(const uint8_t *const p0,
                              const size_t &length) = 0;
  virtual inline void transformByte(const uint8_t &byte) = 0;

  virtual void init() = 0;

  virtual inline size_t getHashSizeBits() = 0;
  virtual void getHash(uint8_t *const hash) = 0;

protected:
  template<class T>
  inline static T LeftRotate(const T &n, const size_t &s) {
    return (n << s) ^ (n >> ((sizeof(T) << 3) - s));
  }
  template<class T>
  inline static T RightRotate(const T &n, const size_t &s) {
    return (n >> s) ^ (n << ((sizeof(T) << 3) - s));
  }
};
}
#endif // !HASHALGORITHM_H