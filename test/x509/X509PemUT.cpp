/*
* Copyright (c) 2018 Pawel Drzycimski
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*
*/


#include <gtest/gtest.h>

#include <simpleopenssl/simpleopenssl.hpp>
#include "../precalculated.h"
#include "../utils.h"

namespace so { namespace ut { namespace x509 {

namespace x509 = ::so::x509;

TEST(X509PEMUT, pemStringToX509ShouldFail)
{
  // WHEN
  auto cert = x509::convertPemToX509(data::meaninglessInvalidPemCert);
  
  // THEN
  EXPECT_FALSE(cert);
}

TEST(X509PEMUT, pemStringToX509ShouldSuccess)
{
  // WHEN
  auto cert = x509::convertPemToX509(data::selfSignedCAPemCert);
  
  // THEN
  EXPECT_TRUE(cert);
}

TEST(X509PEMUT, x509ToPem)
{
  // GIVEN
  const auto pemCert = data::selfSignedCAPemCert;
  BIO_uptr bio = make_unique(BIO_new(BIO_s_mem()));
  ASSERT_TRUE(bio);
  ASSERT_TRUE(BIO_write(bio.get(), pemCert.c_str(), static_cast<int>(pemCert.length())));

  auto cert = make_unique(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(cert);

  //WHEN
  const auto actual = x509::convertX509ToPem(*cert);

  //THEN
  ASSERT_TRUE(actual);
  EXPECT_EQ(pemCert, actual.value);
}

TEST(X509PEMUT, pemFileToX509)
{
  // WHEN
  auto cert = x509::convertPemFileToX509("data/validpemcert.pem");
  ASSERT_TRUE(cert);

  auto pemCert = x509::convertX509ToPem(*cert.value);
  ASSERT_TRUE(pemCert);

  // THEN
  EXPECT_EQ(pemCert.value, data::selfSignedCAPemCert); 
}

TEST(X509PEMUT, x509ToPemFile)
{
  // GIVEN
  const std::string tmpFilePath = "data/tmp_test_cert.pem";
  const std::string validPemCertFile = "data/validpemcert.pem";
  auto cert = x509::convertPemFileToX509(validPemCertFile);
  ASSERT_TRUE(cert);

  // WHEN
  const auto result = x509::convertX509ToPemFile(*cert.value, tmpFilePath);
  ASSERT_TRUE(result);

  const auto fileGuard = makeScopeGuard([&]{ removeFile(tmpFilePath); });

  const auto correctFileHash = so::hash::fileSHA256(validPemCertFile.c_str(), validPemCertFile.size());
  ASSERT_TRUE(correctFileHash);
  const auto actualFileHash = so::hash::fileSHA256(tmpFilePath.c_str(), tmpFilePath.size());
  ASSERT_TRUE(actualFileHash);

  // THEN
  EXPECT_EQ(correctFileHash.value, actualFileHash.value);
}

}}}
