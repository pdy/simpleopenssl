#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <simpleopenssl/simpleopenssl.h>
#include "precalculated.h"

namespace so { namespace ut { namespace x509 {

namespace x509 = ::so::x509;

TEST(X509UT, pemStringToX509ShouldFail)
{
  // WHEN
  auto cert = x509::pem2X509(data::meaninglessInvalidPemCert);
  
  // THEN
  EXPECT_FALSE(cert);
}

TEST(X509UT, pemStringToX509ShouldSuccess)
{
  // WHEN
  auto cert = x509::pem2X509(data::meaninglessValidPemCert);
  
  // THEN
  EXPECT_TRUE(cert);
}

}}}
