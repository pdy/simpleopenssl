#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <simpleopenssl/simpleopenssl.h>
#include "precalculated.h"

namespace so { namespace ut { namespace x509 {

namespace x509 = ::so::x509;

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

TEST(X509UT, setGetSubjectAPIIntegrityOK)
{
  // GIVEN
  x509::Info info;
  info.commonName = "Simple Joe";
  info.countryName = "US";
  info.stateOrProvinceName = "Utah";

  auto cert = ::so::make_unique(X509_new());

  // WHEN
  const auto setResult = x509::setSubject(*cert, info);
  const auto getResult = x509::subject(*cert);

  // THEN
  ASSERT_TRUE(setResult);
  ASSERT_TRUE(getResult);
  EXPECT_EQ(info, *getResult);
}

TEST(X509UT, getVersionOK)
{
  // GIVEN
  const long expected = 3;
  auto cert = ::so::make_unique(X509_new());
  ASSERT_TRUE(cert);
  ASSERT_TRUE(X509_set_version(cert.get(), expected - 1));

  // WHEN
  const auto actual = x509::version(*cert);

  // THEN
  ASSERT_TRUE(actual);
  EXPECT_EQ(expected, *actual);
}

TEST(X509UT, getSetVersionApiIntegrityOK)
{
  // GIVEN
  const long expected = 3;
  auto cert = ::so::make_unique(X509_new());
  ASSERT_TRUE(cert);

  // WHEN
  const auto setResult = x509::setVersion(*cert, expected);
  const auto actual = x509::version(*cert);

  // THEN
  ASSERT_TRUE(setResult);
  ASSERT_TRUE(actual);
  EXPECT_EQ(expected, *actual);
}

TEST(X509UT, getValidityOK)
{
  // GIVEN
  const long notAfterSeconds = 50000;
  const long notBeforeSeconds = 0;
  const auto now = std::chrono::system_clock::now();
  const auto notAfter = std::chrono::system_clock::to_time_t(now + std::chrono::seconds(notAfterSeconds));
  const auto notBefore = std::chrono::system_clock::to_time_t(now + std::chrono::seconds(notBeforeSeconds));
  ::so::ASN1_TIME_uptr notAfterTime = ::so::make_unique(ASN1_TIME_set(nullptr, notAfter));
  ::so::ASN1_TIME_uptr notBeforeTime = ::so::make_unique(ASN1_TIME_set(nullptr, notBefore));
  ASSERT_TRUE(notAfterTime);
  ASSERT_TRUE(notBeforeTime);
  auto cert = ::so::make_unique(X509_new());
  ASSERT_TRUE(cert);
  ASSERT_TRUE(X509_set1_notBefore(cert.get(), notBeforeTime.get()));
  ASSERT_TRUE(X509_set1_notAfter(cert.get(), notAfterTime.get()));

  const ::so::x509::Validity expected {notAfter, notBefore};

  // WHEN
  const auto validity = x509::validity(*cert);

  // THEN
  ASSERT_TRUE(validity);
  EXPECT_EQ(expected, *validity);
}

TEST(X509UT, getSetValidityAPIIntegrityOK)
{
  // GIVEN
  const long notAfterSeconds = 50000;
  const long notBeforeSeconds = 0;
  const auto now = std::chrono::system_clock::now();
  const auto notAfter = std::chrono::system_clock::to_time_t(now + std::chrono::seconds(notAfterSeconds));
  const auto notBefore = std::chrono::system_clock::to_time_t(now + std::chrono::seconds(notBeforeSeconds));
  const ::so::x509::Validity expected {notAfter, notBefore};
  auto cert = ::so::make_unique(X509_new());
  ASSERT_TRUE(cert);

  // WHEN
  const auto setResult = x509::setValidity(*cert, expected);
  const auto maybeValidity = x509::validity(*cert);

  // THEN
  EXPECT_TRUE(setResult);
  ASSERT_TRUE(maybeValidity);
  EXPECT_EQ(expected, *maybeValidity);
}

}}}
