#include <simpleopenssl/simpleopenssl.h>
#include <gtest/gtest.h>
#include "utils.h"

using namespace so;

TEST(NidUT, cmp)
{
  EXPECT_EQ(nid::AACONTROLS, nid::Nid(NID_aaControls));
  EXPECT_NE(nid::AACONTROLS, nid::ACCOUNT);
}

