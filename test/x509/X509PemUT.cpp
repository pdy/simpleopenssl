#include <gtest/gtest.h>

#include <simpleopenssl/simpleopenssl.h>
#include "../precalculated.h"

namespace so { namespace ut { namespace x509 {

namespace x509 = ::so::x509;

TEST(X509UT, pemStringToX509ShouldFail)
{
  // WHEN
  auto cert = x509::convertPemToX509(data::meaninglessInvalidPemCert);
  
  // THEN
  EXPECT_FALSE(cert);
}

TEST(X509UT, pemStringToX509ShouldSuccess)
{
  // WHEN
  auto cert = x509::convertPemToX509(data::meaninglessValidPemCert);
  
  // THEN
  EXPECT_TRUE(cert);
}

TEST(X509UT, x509ToPem)
{
  // GIVEN
  const auto pemCert = data::meaninglessValidPemCert;
  BIO_uptr bio = make_unique(BIO_new(BIO_s_mem()));
  ASSERT_TRUE(bio);
  ASSERT_TRUE(BIO_write(bio.get(), pemCert.c_str(), static_cast<int>(pemCert.length())));

  auto cert = make_unique(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(cert);

  //WHEN
  const auto actual = x509::convertX509ToPem(*cert);

  //THEN
  ASSERT_TRUE(actual);
  EXPECT_EQ(pemCert, *actual);
}

}}}
