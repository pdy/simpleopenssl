/*
*  MIT License
*  
*  Copyright (c) 2020 Pawel Drzycimski
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

inline std::string bin2Hex(const so::Bytes &buff)
{
  std::ostringstream oss;
  for(const auto bt : buff){
    oss << std::setfill('0') << std::setw(2) << std::hex << +bt;
  }
  return oss.str(); 
}

inline std::string toString(const so::Bytes &bt)
{
  std::ostringstream ss;
  std::copy(bt.begin(), bt.end(), std::ostream_iterator<char>(ss, ""));
  return ss.str();
}

inline so::Bytes toBytes(const std::string &str)
{
  so::Bytes ret;
  ret.reserve(str.size());
  std::transform(str.begin(), str.end(), std::back_inserter(ret), [](char chr){
      return static_cast<uint8_t>(chr);
  });

  return ret;
}

inline so::Bytes readBinaryFile(const std::string &filePath)
{
  std::ifstream input(filePath.c_str(), std::ios::binary);
  if(!input.is_open())
    return {};

  input.seekg(0, std::ios::end);
  const auto size = input.tellg();
  input.seekg(0, std::ios::beg);

  so::Bytes ret(static_cast<size_t>(size));
  input.read(reinterpret_cast<char*>(ret.data()), size);
  input.close();

  return ret;
}

inline bool operator==(const ::so::Bytes &lhs, const ::so::Bytes &rhs)
{
  return lhs.size() == rhs.size() &&
    std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

}}}

template<typename FUNC>
class ScopeGuard final
{
public:
  ScopeGuard(FUNC &&func)
    : m_func{std::move(func)}
  {}

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

#endif
