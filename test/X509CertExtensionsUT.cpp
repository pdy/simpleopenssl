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
  const auto extCount = x509::extensionsCount(*cert);

  // THEN
  const size_t expected = 0;  
  EXPECT_TRUE(extCount);
  EXPECT_EQ(expected, *extCount);
}

TEST(X509CertExtensionsUT, getExtensions)
{
  // GIVEN
  auto maybeCert = x509::pemToX509(data::meaninglessValidPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();

  // WHEN
  const auto extCount = x509::extensionsCount(*cert);
  const auto extensions = x509::extensions(*cert);
  
  // THEN
  ASSERT_TRUE(extCount);
  ASSERT_TRUE(extensions);
  EXPECT_EQ(*extCount, (*extensions).size());
}

}}}
