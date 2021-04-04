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
  auto cert = x509::convertPemToX509(data::selfSignedCAPemCert);
  
  // THEN
  EXPECT_TRUE(cert);
}

TEST(X509UT, x509ToPem)
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

}}}
