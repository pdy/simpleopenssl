#include <gtest/gtest.h>

#include <simpleopenssl/simpleopenssl.h>
#include "precalculated.h"
#include "utils.h"

namespace so { namespace ut { namespace x509 {

namespace x509 = ::so::x509;

TEST(CRLUT, version)
{
  // GIVEN 
  auto mcrl = x509::convertPemToCRL(data::validPemCRL);
  ASSERT_TRUE(mcrl);
  auto crl = mcrl.moveValue();

  // WHEN
  const auto version = x509::getVersion(*crl);

  // THEN
  EXPECT_EQ(x509::Version::v2, std::get<0>(version));
  EXPECT_EQ(1, std::get<1>(version));
}

TEST(CRLUT, revCount)
{
  // GIVEN 
  auto mcrl = x509::convertPemToCRL(data::validPemCRL);
  ASSERT_TRUE(mcrl);
  auto crl = mcrl.moveValue();

  // WHEN
  const auto revCount = x509::getRevokedCount(*crl);
 
  // THEN 
  EXPECT_EQ(5, revCount);
}

TEST(CRLUT, getRevokedCount)
{
  // GIVEN 
  auto mcrl = x509::convertPemToCRL(data::validPemCRL);
  ASSERT_TRUE(mcrl);
  auto crl = mcrl.moveValue(); 


  // WHEN
  const auto revoked = x509::getRevoked(*crl);
 
  // THEN 
  ASSERT_TRUE(revoked);
  EXPECT_EQ(5, revoked->size());
}

TEST(CRLUT, getIssuer)
{
  // GIVEN 
  auto mcrl = x509::convertPemToCRL(data::validPemCRL);
  ASSERT_TRUE(mcrl);
  auto crl = mcrl.moveValue(); 


  // WHEN
  const auto issuer = x509::getIssuer(*crl);
 
  // THEN 
  ASSERT_TRUE(issuer);
  EXPECT_EQ("Sample Signer Cert", issuer->commonName);
  EXPECT_EQ("Sample Signer Organization", issuer->organizationName);
  EXPECT_EQ("Sample Signer Unit", issuer->organizationalUnitName);

}

TEST(CRLUT, getCrlExtensionsCount)
{
  // GIVEN 
  auto mcrl = x509::convertPemToCRL(data::validPemCRL);
  ASSERT_TRUE(mcrl);
  auto crl = mcrl.moveValue(); 


  // WHEN
  const auto count = x509::getExtensionsCount(*crl);
 
  // THEN 
  ASSERT_TRUE(count);
  EXPECT_EQ(2, *count);
}

TEST(CRLUT, getCrlExtensions)
{
  // GIVEN 
  auto mcrl = x509::convertPemToCRL(data::validPemCRL);
  ASSERT_TRUE(mcrl);
  auto crl = mcrl.moveValue(); 


  // WHEN
  const auto exts = x509::getExtensions(*crl);
 
  // THEN 
  ASSERT_TRUE(exts);
  ASSERT_EQ(2, exts->size());
  
  const auto first = exts->at(0);
  EXPECT_EQ(nid::Nid::AUTHORITY_KEY_IDENTIFIER, static_cast<nid::Nid>(first.id));
  EXPECT_EQ(std::string("keyid:BE:12:01:CC:AA:EA:11:80:DA:2E:AD:B2:EA:C7:B5:FB:9F:F9:AD:34\n"),
            utils::toString(first.data));

  const auto sec = exts->at(1);
  EXPECT_EQ(x509::CrlExtensionId::CRL_NUMBER, sec.id);
  EXPECT_EQ("3", utils::toString(sec.data));
}

TEST(CRLUT, getCrlSignarueAlgo)
{
  // GIVEN 
  auto mcrl = x509::convertPemToCRL(data::validPemCRL);
  ASSERT_TRUE(mcrl);
  auto crl = mcrl.moveValue(); 


  // WHEN
  const auto algo = x509::getSignatureAlgorithm(*crl);
 
  // THEN 
  EXPECT_EQ(nid::Nid::SHA1WITHRSAENCRYPTION, algo);
}

}}} // namespace so { namespace ut { namespace x509 {
