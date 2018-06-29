#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <numeric>
#include <simpleopenssl/simpleopenssl.h>
#include "precalculated.h"

namespace so { namespace ut { namespace x509 {

namespace x509 = ::so::x509;

namespace {
  std::ostream& operator<<(std::ostream &oss, const x509::CertExtension &ext)
  {
    oss << "Name [" << ext.name << "] oid [" << ext.oidNumerical << "] Data [";
    std::copy(ext.data.begin(), ext.data.end(), std::ostream_iterator<char>(oss, ""));
    return oss << "]\n";
  }
}

TEST(X509CertExtensionsUT, getExtensionCountShouldEqualToZeor)
{
  // GIVEN
  auto cert = so::make_unique(X509_new());

  // WHEN
  const auto extCount = x509::getExtensionsCount(*cert);

  // THEN
  const size_t expected = 0;  
  EXPECT_TRUE(extCount);
  EXPECT_EQ(expected, *extCount);
}

TEST(X509CertExtensionsUT, getExtensionsCountShouldEqualToThree)
{
  // GIVEN
  auto maybeCert = x509::pemToX509(data::meaninglessValidPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();

  // WHEN
  const auto extCount = x509::getExtensionsCount(*cert);
  
  // THEN
  ASSERT_TRUE(extCount);
  EXPECT_EQ(3, *extCount);
}

TEST(X509CertExtensionsUT, getExtensions)
{
  // GIVEN
  auto maybeCert = x509::pemToX509(data::meaninglessValidPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();

  // WHEN
  const auto extCount = x509::getExtensionsCount(*cert);
  const auto extensions = x509::getExtensions(*cert);
  
  // THEN
  ASSERT_TRUE(extCount);
  ASSERT_TRUE(extensions);
  EXPECT_EQ(*extCount, (*extensions).size());
}

TEST(X509CertExtensionsUT, getExtensionKeyUsage)
{
  // GIVEN
  auto maybeCert = x509::pemToX509(data::meaninglessValidPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();

  // WHEN
  const auto extension = x509::getExtension(*cert, x509::CertExtensionId::KEY_USAGE);
  
  // THEN
  ASSERT_TRUE(extension);
  std::cout << *extension;
  EXPECT_EQ(x509::CertExtensionId::KEY_USAGE, (*extension).id);
}

TEST(X509CertExtensionsUT, getExtensionShouldReturnErrorWhenExtensionDoesNotExists)
{
  // GIVEN
  auto maybeCert = x509::pemToX509(data::meaninglessValidPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();

  // WHEN
  const auto extension = x509::getExtension(*cert, x509::CertExtensionId::TLS_FEATURE);
  
  // THEN
  ASSERT_FALSE(extension);
}

}}}
