#include <gtest/gtest.h>

#include <simpleopenssl/simpleopenssl.h>
#include "../precalculated.h"

namespace so { namespace ut { namespace x509 {

namespace x509 = ::so::x509;

TEST(CRLPemUT, pemStringToCRLShouldFail)
{
  // WHEN
  auto crl = x509::convertPemToCRL(data::invalidPemCRL);
  
  // THEN
  EXPECT_FALSE(crl);
}

TEST(CRLPemUT, pemStringToCRLShouldSuccess)
{
  // WHEN
  auto crl = x509::convertPemToCRL(data::validPemCRL);
  
  // THEN
  EXPECT_TRUE(crl);
}

TEST(CRLPemUT, crlToPem)
{
  // GIVEN
  const auto pemCrl = data::validPemCRL;
  BIO_uptr bio = make_unique(BIO_new(BIO_s_mem()));
  ASSERT_TRUE(bio);
  ASSERT_TRUE(BIO_write(bio.get(), pemCrl.c_str(), static_cast<int>(pemCrl.length())));

  auto crl = make_unique(PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(crl);

  //WHEN
  const auto actual = x509::convertCrlToPem(*crl);

  //THEN
  ASSERT_TRUE(actual);
  EXPECT_EQ(pemCrl, *actual);
}
}}}
