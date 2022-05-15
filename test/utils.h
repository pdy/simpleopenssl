/*
*  MIT License
*  
*  Copyright (c) 2020 - 2022 Pawel Drzycimski
*  
*  Permission is hereby granted, free of charge, to any person obtaining a copy
*  of this software and associated documentation files (the "Software"), to deal
*  in the Software without restriction, including without limitation the rights
*  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
*  copies of the Software, and to permit persons to whom the Software is
*  furnished to do so, subject to the following conditions:
*  
*  The above copyright notice and this permission notice shall be included in all
*  copies or substantial portions of the Software.
*  
*  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
*  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
*  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
*  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
*  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
*  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
*  SOFTWARE.
*
*/


#ifndef PDY_SO_TESTS_UTILS_H_
#define PDY_SO_TESTS_UTILS_H_

#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>
#include <iterator>
#include <fstream>

#include "platform.h"
#include "simpleopenssl/simpleopenssl.h"


namespace so { namespace ut { namespace utils {

namespace internal {

inline std::vector<uint8_t> doHashFile(const std::string &path, const EVP_MD *evpMd)
{    
  auto bioRaw = make_unique(BIO_new_file(path.c_str(), "rb"));
  if(!bioRaw)
    return std::vector<uint8_t>{}; 

  // mdtmp will be freed with bio
  BIO *mdtmp = BIO_new(BIO_f_md());
  if(!mdtmp)
    return std::vector<uint8_t>{};

  // WTF OpenSSL?
  // Every EVP_<digest>() function returns const pointer, but
  // BIO_set_md which supposed to consume this pointer takes.... non const!
  // WTF OpenSSL?
  BIO_set_md(mdtmp, const_cast<EVP_MD*>(evpMd));
  auto bio = make_unique(BIO_push(mdtmp, bioRaw.release()));
  if(!bio)
    return std::vector<uint8_t>{};

  {
    char buf[10240];
    int rdlen;
    do {
      char *bufFirstPos = buf;
      rdlen = BIO_read(bio.get(), bufFirstPos, sizeof(buf));
    } while (rdlen > 0);
  }

  uint8_t mdbuf[EVP_MAX_MD_SIZE];
  const int mdlen = BIO_gets(mdtmp, reinterpret_cast<char*>(mdbuf), EVP_MAX_MD_SIZE);

  return std::vector<uint8_t>(std::begin(mdbuf), std::next(std::begin(mdbuf), mdlen));
}

} // namespace internal

inline bool equals(const ::so::ByteBuffer &buff, const ::so::OsslByteBuffer &osslBuffer)
{
  return osslBuffer.size == buff.size && std::equal(osslBuffer.begin(), osslBuffer.end(), buff.begin());
}

inline bool equals(const ::so::OsslByteBuffer &osslBuffer, const ::so::ByteBuffer &buff)
{
  return osslBuffer.size == buff.size && std::equal(osslBuffer.begin(), osslBuffer.end(), buff.begin());
}

template <typename T>
void add_to_vector(std::vector<T>* /*vec*/) {}

template <typename T, typename... Args>
void add_to_vector(std::vector<T>* vec, T&& car, Args&&... cdr) {
  vec->push_back(std::forward<T>(car));
  add_to_vector(vec, std::forward<Args>(cdr)...);
}

template <typename T, typename... Args>
std::vector<T> make_vector(Args&&... args) {
  std::vector<T> result;
  add_to_vector(&result, std::forward<Args>(args)...);
  return result;
}

inline ::so::ByteBuffer copy(const ::so::ByteBuffer &buff)
{
  ::so::ByteBuffer ret(buff.size);
  std::copy(buff.begin(), buff.end(), ret.begin());
  return ret;
}

inline bool equal(const ::so::ByteBuffer &lhs, unsigned char *rhs, int rhsLen)
{
  if(static_cast<int>(lhs.size) != rhsLen)
    return false;

  size_t idx = 0;
  for(const auto &bt : lhs)
  {
    if(bt != rhs[idx])
      return false;

    ++idx;
  }

  return true;
}

inline std::string bin2Hex(const so::ByteBuffer &buff)
{
  std::ostringstream oss;
  for(const auto bt : buff){
    oss << std::setfill('0') << std::setw(2) << std::hex << +bt;
  }
  return oss.str(); 
}

inline std::string bin2Hex(const std::vector<uint8_t> &buff)
{
  std::ostringstream oss;
  for(const auto bt : buff){
    oss << std::setfill('0') << std::setw(2) << std::hex << +bt;
  }
  return oss.str(); 
}

inline std::string toString(const ::so::ByteBuffer &bt)
{
  std::ostringstream ss;
  std::copy(bt.begin(), bt.end(), std::ostream_iterator<char>(ss, ""));
  return ss.str();
}

inline ::so::ByteBuffer toBytes(const std::string &str)
{
  ::so::ByteBuffer ret(str.size());
  std::transform(str.begin(), str.end(), ret.begin(), [](char chr){
      return static_cast<uint8_t>(chr);
  });

  return ret;
}

inline ::so::ByteBuffer toByteBuffer(const std::vector<uint8_t> &vbt)
{
  ::so::ByteBuffer ret(vbt.size());
  std::copy(vbt.begin(), vbt.end(), ret.begin());
  return ret;
}

inline ::so::ByteBuffer readBinaryFile(const std::string &filePath)
{
  std::ifstream input(filePath.c_str(), std::ios::binary);
  if(!input.is_open())
    return {};

  input.seekg(0, std::ios::end);
  const auto size = input.tellg();
  input.seekg(0, std::ios::beg);

  ::so::ByteBuffer ret(static_cast<size_t>(size));
  input.read(reinterpret_cast<char*>(ret.get()), size);
  input.close();

  return ret;
}

inline bool operator==(const std::vector<uint8_t> &lhs, const std::vector<uint8_t> &rhs)
{
  return lhs.size() == rhs.size() &&
    std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

inline bool filesEqual(const std::string &file_1, const std::string &file_2)
{
  const auto file_1_hash = internal::doHashFile(file_1, EVP_sha256());
  const auto file_2_hash = internal::doHashFile(file_2, EVP_sha256());

  return file_1_hash == file_2_hash;
}

}}}

template<typename FUNC>
class ScopeGuard final
{
public:
  explicit ScopeGuard(FUNC &&func)
    : m_func{std::move(func)}
  {}

  ScopeGuard(const ScopeGuard&) = delete;
  ScopeGuard(ScopeGuard&&) = default;

  ~ScopeGuard()
  {
    try{
      m_func();
    }catch(...)
    {
      std::cout << "ScopeGuard exception\n";
    }

  }
private:
  FUNC m_func;

};

template<typename T>
ScopeGuard<T> makeScopeGuard(T &&func)
{
  return ScopeGuard<T>(std::move(func));
}

inline std::string osslLastError()
{
    static constexpr size_t SIZE = 1024;
    char buff[SIZE];
    std::memset(buff, 0x00, SIZE);
    ERR_error_string_n(ERR_get_error(), buff, SIZE);
    return std::string(buff);

}

#endif
