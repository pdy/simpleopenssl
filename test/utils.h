#ifndef PDY_SO_TESTS_UTILS_H_
#define PDY_SO_TESTS_UTILS_H_

#include <iomanip>
#include <sstream>
#include <vector>
#include <iterator>

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

}}}

#endif
