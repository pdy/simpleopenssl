#include <simpleopenssl/simpleopenssl.h>
#include <gtest/gtest.h>
#include "utils.h"

using namespace so;

struct NidUTInput
{
  int rawNid;
  nid::Nid soNid;
};

class NidValidityUT : public ::testing::TestWithParam<NidUTInput>
{};

TEST_P(NidValidityUT, cmp)
{
  const auto input {GetParam()};
  
  EXPECT_EQ(input.rawNid, input.soNid.getRaw());
}

const auto testCases = ::testing::Values(
  NidUTInput {
    NID_undef, nid::UNDEF
  },
  NidUTInput {
    NID_aaControls, nid::AACONTROLS
  }
);

INSTANTIATE_TEST_CASE_P(
    Nid,
    NidValidityUT,
    testCases 
);
