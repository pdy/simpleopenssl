#ifndef SEVERALGH_SO_TESTS_UTILS_H_
#define SEVERALGH_SO_TESTS_UTILS_H_

#include <iomanip>
#include <sstream>
#include <vector>

namespace so { namespace ut { namespace utils {

inline std::string bin2Hex(const std::vector<uint8_t> &buff)
{
  std::ostringstream oss;
  for(const auto bt : buff){
    oss << std::setfill('0') << std::setw(2) << std::hex << +bt;
  }
  return oss.str(); 
}

}}}

#endif
