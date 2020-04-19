#include <gtest/gtest.h>

#include <simpleopenssl/simpleopenssl.h>
#include "precalculated.h"

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

TEST(CRLUT, getRevoked)
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

}}} // namespace so { namespace ut { namespace x509 {
