#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <numeric>
#include <simpleopenssl/simpleopenssl.h>
#include "precalculated.h"

namespace so { namespace ut { namespace x509 {

namespace x509 = ::so::x509;

TEST(X509CertExtensionsUT, getExtensionCount)
{
  // GIVEN
  auto cert = so::make_unique(X509_new());

  // WHEN
  const auto extensions = x509::extensionsCount(*cert);

  // THEN
  const size_t expected = 0;  
  EXPECT_TRUE(extensions);
  EXPECT_EQ(expected, *extensions);
}


}}}
