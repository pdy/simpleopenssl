#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <simpleopenssl/simpleopenssl.h>
#include "precalculated.h"

namespace so { namespace ut { namespace x509 {

namespace x509 = ::so::x509;

struct InitGuard
{
  InitGuard() { so::init(); }
  ~InitGuard() { so::cleanUp(); }
};

TEST(X509UT, pemStringToX509ShouldFail)
{
  InitGuard init;

  // WHEN
  auto cert = x509::pem2X509(data::meaninglessInvalidPemCert);
  
  // THEN
  EXPECT_FALSE(cert);
}

TEST(X509UT, pemStringToX509ShouldSuccess)
{
  InitGuard init;

  // WHEN
  auto cert = x509::pem2X509(data::meaninglessValidPemCert);
  std::cout << cert.msg() << std::endl;  
  // THEN
  EXPECT_TRUE(cert);
}

TEST(X509UT, getIssuerOK)
{
  // GIVEN  
  auto issuer = so::make_unique(X509_NAME_new());
  ASSERT_TRUE(X509_NAME_add_entry_by_NID(issuer.get(), NID_countryName, MBSTRING_ASC, reinterpret_cast<const unsigned char*>("UK"), -1, -1, 0));
  ASSERT_TRUE(X509_NAME_add_entry_by_NID(issuer.get(), NID_organizationName, MBSTRING_ASC, reinterpret_cast<const unsigned char*>("Unorganized"), -1, -1, 0));
  ASSERT_TRUE(X509_NAME_add_entry_by_NID(issuer.get(), NID_commonName, MBSTRING_ASC, reinterpret_cast<const unsigned char*>("Joe Briggs"), -1, -1, 0));

  auto cert = so::make_unique(X509_new());
  ASSERT_TRUE(X509_set_issuer_name(cert.get(), issuer.get()));

  // WHEN
  auto actual = x509::issuer(*cert);

  // THEN
  ASSERT_TRUE(actual);
  EXPECT_EQ("UK", (*actual).countryName);
  EXPECT_EQ("Unorganized", (*actual).organizationName);
  EXPECT_EQ("Joe Briggs", (*actual).commonName);
}

}}}
