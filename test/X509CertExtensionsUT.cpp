#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <numeric>
#include <simpleopenssl/simpleopenssl.h>

#include "precalculated.h"
#include "utils.h"

namespace so { namespace ut { namespace x509 {

namespace x509 = ::so::x509;

/*
namespace {

  inline std::ostream& operator<<(std::ostream &oss, const x509::CertExtension &ext)
  {
    oss << "Name [" << ext.name << "] oid [" << ext.oidNumerical << "] Data [";
    std::copy(ext.data.begin(), ext.data.end(), std::ostream_iterator<char>(oss, ""));
    return oss << "] " << "critical [" << ext.critical << "]\n";
  }
 
} // anonymous namespace 
*/

TEST(X509CertExtensionsUT, getExtensionCountShouldEqualToZero)
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
  const std::vector<x509::CertExtension> expected {
    {
      x509::CertExtensionId::SUBJECT_KEY_IDENTIFIER,
      false,
      "X509v3 Subject Key Identifier",
      "2.5.29.14",
      utils::toBytes("75:71:A7:19:48:19:BC:9D:9D:EA:41:47:DF:94:C4:48:77:99:D3:79")
    },
    {
      x509::CertExtensionId::KEY_USAGE,
      true,
      "X509v3 Key Usage",
      "2.5.29.15",
      utils::toBytes("Certificate Sign, CRL Sign")
    },
    {
      x509::CertExtensionId::BASIC_CONSTRAINTS,
      true,
      "X509v3 Basic Constraints",
      "2.5.29.19",
      utils::toBytes("CA:TRUE")
    } 
  };
  
  auto maybeCert = x509::pemToX509(data::meaninglessValidPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();

  // WHEN
  const auto extCount = x509::getExtensionsCount(*cert);
  const auto extensions = x509::getExtensions(*cert);
  

  // THEN
  ASSERT_TRUE(extCount);
  ASSERT_TRUE(extensions);
  ASSERT_EQ(*extCount, (*extensions).size());
  ASSERT_EQ(expected.size(), (*extensions).size());
  ASSERT_EQ(expected, (*extensions));
}

TEST(X509CertExtensionsUT, getExtensionKeyUsage)
{
  // GIVEN
  const x509::CertExtension expected {
    x509::CertExtensionId::KEY_USAGE,
    true,
    "X509v3 Key Usage",
    "2.5.29.15",
    utils::toBytes("Certificate Sign, CRL Sign")
  };

  auto maybeCert = x509::pemToX509(data::meaninglessValidPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();

  // WHEN
  const auto extension = x509::getExtension(*cert, x509::CertExtensionId::KEY_USAGE);
  
  // THEN
  ASSERT_TRUE(extension);
  EXPECT_EQ(expected, *extension);
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

TEST(X509CertExtensionsUT, addCustomExtensionAPIIntegrity)
{
  // GIVEN
  const x509::CertExtension expected {
    x509::CertExtensionId::UNDEF,
    false,
    "",
    // intel net adapter found at http://oid-info.com
    "1.3.6.1.4.1.343.2.7.2",
    {0xaa, 0xbb}
  }; 
  auto cert = so::make_unique(X509_new());
  ASSERT_TRUE(cert);
  auto maybeData = so::asn1::encodeOctet(expected.data);
  ASSERT_TRUE(maybeData);
  auto data = maybeData.moveValue();

  // WHEN
  const auto addResult = x509::setCustomExtension(*cert, expected.oidNumerical, *data);
  auto getResult = x509::getExtensions(*cert);

  // THEN
  ASSERT_TRUE(addResult);
  ASSERT_TRUE(getResult);
  ASSERT_EQ(1, (*getResult).size());
  EXPECT_EQ(expected, (*getResult).at(0));
}

TEST(X509CertExtensionsUT, addCustomExtensionToAlreadyExistingStandardExtensions)
{
  // GIVEN
  const x509::CertExtension expected {
    x509::CertExtensionId::UNDEF,
    false,
    "",
    // intel net adapter found at http://oid-info.com
    "1.3.6.1.4.1.343.2.7.2",
    {0xaa, 0xbb}
  }; 
  auto maybeCert = x509::pemToX509(data::meaninglessValidPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();
  auto maybeData = so::asn1::encodeOctet(expected.data);
  ASSERT_TRUE(maybeData);
  auto data = maybeData.moveValue();

  // WHEN
  const auto addResult = x509::setCustomExtension(*cert, expected.oidNumerical, *data);
  auto getResult = x509::getExtensions(*cert);

  // THEN
  ASSERT_TRUE(addResult);
  ASSERT_TRUE(getResult);
  ASSERT_EQ(4, (*getResult).size());
  EXPECT_EQ(expected, (*getResult).at(3));
}

}}}
