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
