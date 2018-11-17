#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <numeric>
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
  auto actual = x509::getIssuer(*cert);

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
  auto actual = x509::getSubject(*cert);
  
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
  auto maybeRootCert = x509::convertPemToX509(data::meaninglessValidPemCert);
  ASSERT_TRUE(maybeRootCert);
  auto rootCert = maybeRootCert.moveValue();
  auto rootCertSubj = x509::getSubject(*rootCert);
  ASSERT_TRUE(rootCertSubj);

  auto cert = ::so::make_unique(X509_new());

  // WHEN
  const auto setResult = x509::setIssuer(*cert, *rootCert);
  const auto getResult = x509::getIssuer(*cert);

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
  const auto getResult = x509::getIssuer(*cert);

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
  const auto getResult = x509::getSubject(*cert);

  // THEN
  ASSERT_TRUE(setResult);
  ASSERT_TRUE(getResult);
  EXPECT_EQ(info, *getResult);
}

TEST(X509UT, getVersionOK)
{
  // GIVEN
  const x509::Version expected = x509::Version::v3;
  auto cert = ::so::make_unique(X509_new());
  ASSERT_TRUE(cert);
  ASSERT_TRUE(X509_set_version(cert.get(), static_cast<long>(expected)));

  // WHEN
  const auto actual = x509::getVersion(*cert);

  // THEN
  ASSERT_TRUE(actual);
  EXPECT_EQ(expected, *actual);
}

TEST(X509UT, getVersionShoulNotBeEqual)
{
  // GIVEN
  const x509::Version expected = x509::Version::v3;
  auto cert = ::so::make_unique(X509_new());
  ASSERT_TRUE(cert);
  ASSERT_TRUE(X509_set_version(cert.get(), static_cast<long>(expected) - 1));

  // WHEN
  const auto actual = x509::getVersion(*cert);

  // THEN
  ASSERT_TRUE(actual);
  EXPECT_NE(expected, *actual);
}

TEST(X509UT, getSetVersionApiIntegrityOK)
{
  // GIVEN
  const x509::Version expected = x509::Version::v3;
  auto cert = ::so::make_unique(X509_new());
  ASSERT_TRUE(cert);

  // WHEN
  const auto setResult = x509::setVersion(*cert, expected);
  const auto actual = x509::getVersion(*cert);

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
  const auto validity = x509::getValidity(*cert);

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
  const auto maybeValidity = x509::getValidity(*cert);

  // THEN
  EXPECT_TRUE(setResult);
  ASSERT_TRUE(maybeValidity);
  EXPECT_EQ(expected, *maybeValidity);
}

TEST(X509UT, getSetPubKeyWithGeneratedKey)
{
  /*
   * 1. Generate ec key par
   * 2. Set pub key in x509 cert
   * 3. Extract public key from cert
   * 4. Extracted key should not be able to sign anything
   * 5. Extracted key should be able to verify signature
   */

  // 1.
  auto cert = ::so::make_unique(X509_new());
  auto maybeKey = ::so::ecdsa::generateKey(::so::ecdsa::Curve::sect239k1);
  ASSERT_TRUE(maybeKey);
  auto key = maybeKey.moveValue();
  auto maybePub = ::so::ecdsa::getPublic(*key);
  ASSERT_TRUE(maybePub);
  auto maybeEvpPubKey = ::so::ecdsa::convertToEvp(*maybePub.moveValue());
  ASSERT_TRUE(maybeEvpPubKey);
  auto evpPubKey = maybeEvpPubKey.moveValue();
  auto maybePriv = ::so::ecdsa::convertToEvp(*key);
  ASSERT_TRUE(maybePriv);
  auto evpPrivKey = maybePriv.moveValue();
  
  // 2.
  const auto result = x509::setPubKey(*cert, *evpPubKey);
  ASSERT_TRUE(result);

  // 3.
  auto maybeExtractedPub = x509::getPubKey(*cert);
  ASSERT_TRUE(maybeExtractedPub);
  auto extractedPub = maybeExtractedPub.moveValue();
  
  // 4.
  ::so::Bytes data(256);
  std::iota(data.begin(), data.end(), 0);
  const auto signResult = ::so::evp::signSha1(data, *evpPrivKey);
  ASSERT_TRUE(signResult);
  const auto pubSignResult = ::so::evp::signSha1(data, *extractedPub);
  ASSERT_FALSE(pubSignResult);
  
  // 5.
  const auto verResult = ::so::evp::verifySha1Signature(*signResult, data, *extractedPub);
  ASSERT_TRUE(verResult); 
  EXPECT_TRUE(*verResult);
}

TEST(X509UT, setGetPubWithPrecalculatedKeys)
{
  /*
   * 1. Convert PEM priv and pub to evp
   * 2. Verify keys are valid for sign/verify
   * 3. Set pub key in cert
   * 4. Extracted key from cert should be able to verify
   *
   */

  // 1.
  auto maybePriv = ::so::evp::convertPemToPrivKey(data::secp256k1PrivKeyPem);
  ASSERT_TRUE(maybePriv);
  auto priv = maybePriv.moveValue();
  auto maybePub = ::so::evp::convertPemToPubKey(data::secp256PubKeyPem);
  ASSERT_TRUE(maybePub);
  auto pub = maybePub.moveValue();

  // 2.
  ::so::Bytes data(256);
  std::iota(data.begin(), data.end(), 0);
  const auto signResult = ::so::evp::signSha1(data, *priv);
  ASSERT_TRUE(signResult);
  const auto pubSignResult = ::so::evp::signSha1(data, *pub);
  ASSERT_FALSE(pubSignResult); 
  const auto verResult = ::so::evp::verifySha1Signature(*signResult, data, *pub);
  ASSERT_TRUE(verResult); 
  EXPECT_TRUE(*verResult);

  // 3.
  auto cert = ::so::make_unique(X509_new());
  ASSERT_TRUE(cert);
  
  // 4.
  const auto result = x509::setPubKey(*cert, *pub);
  ASSERT_TRUE(result);

  auto maybeExtractedPub = x509::getPubKey(*cert);
  ASSERT_TRUE(maybeExtractedPub);
  auto extractedPub = maybeExtractedPub.moveValue();

  const auto ver2Result = ::so::evp::verifySha1Signature(*signResult, data, *extractedPub);
  ASSERT_TRUE(ver2Result);
  ASSERT_TRUE(*ver2Result);
}

TEST(X509UT, certSignSha256VerifyAPIIntegrity)
{
  // GIVEN
  x509::Info name;
  name.commonName = "CommonName";
  name.organizationName = "simpleopenssl";
  auto cert = ::so::make_unique(X509_new());
  ASSERT_TRUE(x509::setSubject(*cert, name));
  ASSERT_TRUE(x509::setIssuer(*cert, name));
  auto maybeEcKey = ::so::ecdsa::generateKey(::so::ecdsa::Curve::secp384r1);
  ASSERT_TRUE(maybeEcKey);
  auto maybeKey = ::so::ecdsa::convertToEvp(*maybeEcKey.moveValue());
  ASSERT_TRUE(maybeKey);
  auto key = maybeKey.moveValue();

  // WHEN
  const auto signResult = x509::signSha256(*cert, *key);
  const auto verResult = x509::verifySignature(*cert, *key);

  // THEN
  ASSERT_TRUE(signResult);
  ASSERT_TRUE(verResult);
  EXPECT_TRUE(*verResult);  
}

TEST(X509UT, certSignSha1VerifyAPIIntegrity)
{
  // GIVEN
  x509::Info name;
  name.commonName = "CommonName";
  name.organizationName = "simpleopenssl";
  auto cert = ::so::make_unique(X509_new());
  ASSERT_TRUE(x509::setSubject(*cert, name));
  ASSERT_TRUE(x509::setIssuer(*cert, name));
  auto maybeEcKey = ::so::ecdsa::generateKey(::so::ecdsa::Curve::secp384r1);
  ASSERT_TRUE(maybeEcKey);
  auto maybeKey = ::so::ecdsa::convertToEvp(*maybeEcKey.moveValue());
  ASSERT_TRUE(maybeKey);
  auto key = maybeKey.moveValue();

  // WHEN
  const auto signResult = x509::signSha1(*cert, *key);
  const auto verResult = x509::verifySignature(*cert, *key);

  // THEN
  ASSERT_TRUE(signResult);
  ASSERT_TRUE(verResult);
  EXPECT_TRUE(*verResult);  
}

TEST(X509UT, certSignSha384VerifyAPIIntegrity)
{
  // GIVEN
  x509::Info name;
  name.commonName = "CommonName";
  name.organizationName = "simpleopenssl";
  auto cert = ::so::make_unique(X509_new());
  ASSERT_TRUE(x509::setSubject(*cert, name));
  ASSERT_TRUE(x509::setIssuer(*cert, name));
  auto maybeEcKey = ::so::ecdsa::generateKey(::so::ecdsa::Curve::sect193r1);
  ASSERT_TRUE(maybeEcKey);
  auto maybeKey = ::so::ecdsa::convertToEvp(*maybeEcKey.moveValue());
  ASSERT_TRUE(maybeKey);
  auto key = maybeKey.moveValue();

  // WHEN
  const auto signResult = x509::signSha384(*cert, *key);
  const auto verResult = x509::verifySignature(*cert, *key);

  // THEN
  ASSERT_TRUE(signResult);
  ASSERT_TRUE(verResult);
  EXPECT_TRUE(*verResult);  
}

TEST(X509UT, getSerialNumberWithPrecalculatedData)
{
  // GIVEN
  const std::vector<uint8_t> expected {0x1f, 0x47, 0xaf, 0xaa, 0x62, 0x00, 0x70, 0x50, 0x54, 0x4c, 0x01, 0x9e, 0x9b, 0x63, 0x99, 0x2a};

  auto maybeCert = x509::convertPemToX509(data::meaninglessValidPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();

  // WHEN
  const auto maybeSerial = x509::getSerialNumber(*cert);

  // THEN
  ASSERT_TRUE(maybeSerial);
  auto serial = *maybeSerial;
  EXPECT_TRUE(std::equal(expected.begin(),
      expected.end(),
      serial.begin(),
      serial.end()));
}

TEST(X509UT, getSerialNumber)
{
  // GIVEN
  const long expectedSerialNumber = 10810;
  const std::vector<uint8_t> expectedSerialArray {0x2a, 0x3a};
  auto cert = so::make_unique(X509_new());
  ASSERT_TRUE(cert);
  ASSERT_TRUE(ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), expectedSerialNumber));

  // WHEN
  auto maybeSerial = x509::getSerialNumber(*cert);

  // THEN
  ASSERT_TRUE(maybeSerial);
  auto serial = *maybeSerial;
  EXPECT_TRUE(std::equal(expectedSerialArray.begin(),
      expectedSerialArray.end(),
      serial.begin(),
      serial.end()));
}

TEST(X509UT, getSetSerialNumberAPIIntegrity)
{
  // GIVEN
  std::vector<uint8_t> expected(256);
  std::iota(expected.begin(), expected.end(), 0x10);
  auto cert = so::make_unique(X509_new());
  ASSERT_TRUE(cert);

  // WHEN
  const auto setResult = x509::setSerial(*cert, expected);
  auto getResult = x509::getSerialNumber(*cert);

  // THEN
  ASSERT_TRUE(setResult);
  ASSERT_TRUE(getResult);
  auto serial = *getResult;
  EXPECT_TRUE(std::equal(expected.begin(),
      expected.end(),
      serial.begin(),
      serial.end()));
}

TEST(X509UT, getSetSerialNumberWhenStartsWithZeroShouldReturnWithoutOne)
{
  // GIVEN
  std::vector<uint8_t> expected(256);
  std::iota(expected.begin(), expected.end(), 0x00);
  auto cert = so::make_unique(X509_new());
  ASSERT_TRUE(cert);

  // WHEN
  const auto setResult = x509::setSerial(*cert, expected);
  auto getResult = x509::getSerialNumber(*cert);

  // THEN
  ASSERT_TRUE(setResult);
  ASSERT_TRUE(getResult);
  auto serial = *getResult;
  EXPECT_TRUE(std::equal(std::next(expected.begin()),
      expected.end(),
      serial.begin(),
      serial.end()));
}

TEST(X509UT, getEcdsaSignature)
{
  // GIVEN
  auto maybeCert = x509::convertPemToX509(data::meaninglessValidPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();

  // WHEN
  auto maybeSig = x509::getEcdsaSignature(*cert);

  // THEN
  ASSERT_TRUE(maybeSig);
  const auto& sig = *maybeSig;
  ASSERT_EQ(48, sig.r.size()); // it's secp384r1
  ASSERT_EQ(48, sig.s.size()); // it's secp384r1
}

TEST(X509UT, isSelfSignedShouldBeTrue)
{
  // GIVEN  
  auto name = so::make_unique(X509_NAME_new());
  ASSERT_TRUE(X509_NAME_add_entry_by_NID(name.get(), NID_countryName, MBSTRING_ASC, reinterpret_cast<const unsigned char*>("UK"), -1, -1, 0));
  ASSERT_TRUE(X509_NAME_add_entry_by_NID(name.get(), NID_organizationName, MBSTRING_ASC, reinterpret_cast<const unsigned char*>("Unorganized"), -1, -1, 0));
  ASSERT_TRUE(X509_NAME_add_entry_by_NID(name.get(), NID_commonName, MBSTRING_ASC, reinterpret_cast<const unsigned char*>("Joe Briggs"), -1, -1, 0));

  auto cert = so::make_unique(X509_new());
  ASSERT_TRUE(X509_set_issuer_name(cert.get(), name.get()));
  ASSERT_TRUE(X509_set_subject_name(cert.get(), name.get()));

  // WHEN
  const auto isSelfSigned = x509::isSelfSigned(*cert);

  // THEN
  ASSERT_TRUE(isSelfSigned);
  ASSERT_TRUE(*isSelfSigned);
}

TEST(X509UT, isSelfSignedShouldBeFalse)
{
  // GIVEN  
  auto issuer = so::make_unique(X509_NAME_new());
  ASSERT_TRUE(X509_NAME_add_entry_by_NID(issuer.get(), NID_countryName, MBSTRING_ASC, reinterpret_cast<const unsigned char*>("UK"), -1, -1, 0));
  ASSERT_TRUE(X509_NAME_add_entry_by_NID(issuer.get(), NID_organizationName, MBSTRING_ASC, reinterpret_cast<const unsigned char*>("Unorganized"), -1, -1, 0));
  ASSERT_TRUE(X509_NAME_add_entry_by_NID(issuer.get(), NID_commonName, MBSTRING_ASC, reinterpret_cast<const unsigned char*>("Joe Briggs"), -1, -1, 0));

  auto subject = so::make_unique(X509_NAME_new());
  ASSERT_TRUE(X509_NAME_add_entry_by_NID(subject.get(), NID_countryName, MBSTRING_ASC, reinterpret_cast<const unsigned char*>("UK"), -1, -1, 0));
  ASSERT_TRUE(X509_NAME_add_entry_by_NID(subject.get(), NID_organizationName, MBSTRING_ASC, reinterpret_cast<const unsigned char*>("Unorganized"), -1, -1, 0));
  ASSERT_TRUE(X509_NAME_add_entry_by_NID(subject.get(), NID_commonName, MBSTRING_ASC, reinterpret_cast<const unsigned char*>("Joe Brem"), -1, -1, 0));

  auto cert = so::make_unique(X509_new());
  ASSERT_TRUE(X509_set_issuer_name(cert.get(), issuer.get()));
  ASSERT_TRUE(X509_set_subject_name(cert.get(), subject.get()));

  // WHEN
  const auto isSelfSigned = x509::isSelfSigned(*cert);

  // THEN
  ASSERT_TRUE(isSelfSigned);
  ASSERT_FALSE(*isSelfSigned);
}

TEST(X509UT, getSignatureAPIIntegrityWithEcdsaDerConversion)
{
  // GIVEN
  auto maybeCert = x509::convertPemToX509(data::meaninglessValidPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();

  const auto maybeSignature = x509::getSignature(*cert);
  const auto maybeEcdsaSignature = x509::getEcdsaSignature(*cert);

  ASSERT_TRUE(maybeSignature);
  ASSERT_TRUE(maybeEcdsaSignature);

  // WHEN
  const auto der = ecdsa::convertToDer(*maybeEcdsaSignature);
  ASSERT_TRUE(der);

  // THEN
  EXPECT_EQ(maybeSignature.value().size(), der.value().size());
  ASSERT_TRUE(std::equal(maybeSignature.value().begin(), maybeSignature.value().end(), der.value().begin()));
}

TEST(X509UT, setGetVersionTest)
{
  // GIVEN
  const x509::Version expected = x509::Version::v2;
  auto cert = so::make_unique(X509_new());
  ASSERT_TRUE(cert);

  // WHEN
  auto setResult = x509::setVersion(*cert, expected);
  ASSERT_TRUE(setResult);
  auto getResult = x509::getVersion(*cert);

  // THEN
  ASSERT_TRUE(getResult);
  EXPECT_EQ(expected, *getResult);
}

}}}
