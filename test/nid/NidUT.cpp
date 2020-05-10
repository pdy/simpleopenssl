#include <simpleopenssl/simpleopenssl.h>
#include <gtest/gtest.h>
#include "../utils.h"
#include "NidsTable.h"
#include <vector>

using namespace so;

namespace {

static std::ostream& operator<<(std::ostream &ss, const NidUTInput &input)
{
  return ss << OBJ_nid2sn(input.rawNid) << " [" << input.rawNid << "]";
}

// std::size from c++17 sooo....
template<typename T, size_t N>
size_t arrSize(const T(&)[N]){ return N; }

}

TEST(NidUT, checkIfEnumValuesAreCorrectlyAssigned)
{
  // I dont want to have value parametrized test here cuase it would generate ~1k test cases
  for(size_t i = 0; i < arrSize(NID_VALIDITY_UT_VALUES); ++i)
    EXPECT_EQ(NID_VALIDITY_UT_VALUES[i].rawNid, static_cast<int>(NID_VALIDITY_UT_VALUES[i].soNid));
}

TEST(NidUT, checkStringName)
{
   
  // I dont want to have value parametrized test here cuase it would generate ~1k test cases
  for(size_t i = 0; i < arrSize(NID_VALIDITY_UT_VALUES); ++i)
  {
    const auto nid = NID_VALIDITY_UT_VALUES[i];
    const char *sn = OBJ_nid2sn(nid.rawNid);
    const char *ln = OBJ_nid2ln(nid.rawNid);

    EXPECT_EQ(nid::getShortName(nid.soNid).value(),std::string(sn));
    EXPECT_EQ(nid::getLongName(nid.soNid).value(), std::string(ln));
  }
}

