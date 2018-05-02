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
  EXPECT_EQ("", (*actual).localityName);
  EXPECT_EQ("", (*actual).stateOrProvinceName);
}

TEST(X509UT, getSubjectOK)
{
  // GIVEN  
  auto subject = so::make_unique(X509_NAME_new());
  ASSERT_TRUE(X509_NAME_add_entry_by_NID(subject.get(), NID_countryName, MBSTRING_ASC, reinterpret_cast<const unsigned char*>("UK"), -1, -1, 0));
  ASSERT_TRUE(X509_NAME_add_entry_by_NID(subject.get(), NID_organizationName, MBSTRING_ASC, reinterpret_cast<const unsigned char*>("Unorganized"), -1, -1, 0));
  ASSERT_TRUE(X509_NAME_add_entry_by_NID(subject.get(), NID_commonName, MBSTRING_ASC, reinterpret_cast<const unsigned char*>("Joe Briggs"), -1, -1, 0));

  auto cert = so::make_unique(X509_new());
  ASSERT_TRUE(X509_set_subject_name(cert.get(), subject.get()));

  // WHEN
  auto actual = x509::subject(*cert);

  // THEN
  ASSERT_TRUE(actual);
  EXPECT_EQ("UK", (*actual).countryName);
  EXPECT_EQ("Unorganized", (*actual).organizationName);
  EXPECT_EQ("Joe Briggs", (*actual).commonName);
  EXPECT_EQ("", (*actual).localityName);
  EXPECT_EQ("", (*actual).stateOrProvinceName);
}

TEST(X509UT, setGetIssuerWithAnotherCertAPIIntegrityOK)
{
  // GIVEN
  auto maybeRootCert = x509::pem2X509(data::meaninglessValidPemCert);
  ASSERT_TRUE(maybeRootCert);
  auto rootCert = *maybeRootCert;
  auto rootCertSubj = x509::subject(*rootCert);
  ASSERT_TRUE(rootCertSubj);

  auto cert = ::so::make_unique(X509_new());

  // WHEN
  const auto setResult = x509::setIssuer(*cert, *rootCert);
  const auto getResult = x509::issuer(*cert);

  // THEN
  ASSERT_TRUE(setResult);
  ASSERT_TRUE(getResult);
  EXPECT_EQ(*rootCertSubj, *getResult); 
}

TEST(X509UT, setGetIssuerAPIIntegrityOK)
{
  // GIVEN
  x509::Info info;
  info.commonName = "Simple Joe";
  info.countryName = "US";
  info.stateOrProvinceName = "Utah";

  auto cert = ::so::make_unique(X509_new());

  // WHEN
  const auto setResult = x509::setIssuer(*cert, info);
  const auto getResult = x509::issuer(*cert);

  // THEN
  ASSERT_TRUE(setResult);
  ASSERT_TRUE(getResult);
  EXPECT_EQ(info, *getResult);
}

}}}
