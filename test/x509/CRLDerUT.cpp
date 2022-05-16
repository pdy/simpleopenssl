/*
* Copyright (c) 2022 Pawel Drzycimski
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
#include "../utils.h"
#include "../platform.h"

namespace so { namespace ut { namespace x509 {

namespace x509 = ::so::x509;

TEST(CRLDERUT, certToDerFile)
{
  static constexpr auto TMP_OUT_FILENAME = "data/tmp_der_crl.der";

  const unsigned char *it = data::validDerCrl.get();
  auto crl = ::so::make_unique(d2i_X509_CRL(nullptr, &it, static_cast<long>(data::validDerCrl.size())));
  ASSERT_TRUE(crl);

  auto scope = ::makeScopeGuard([&] { ::removeFile(TMP_OUT_FILENAME); });

  // WHEN
  const auto result = x509::convertCrlToDerFile(*crl, TMP_OUT_FILENAME);

  // THEN
  ASSERT_TRUE(result);
  EXPECT_TRUE(utils::filesEqual("data/validdercrl.der", TMP_OUT_FILENAME));
}

TEST(CRLDERUT, derFileToCert)
{
  // WHEN
  auto crl = x509::convertDerFileToCrl("data/validdercrl.der");

  // THEN
  ASSERT_TRUE(crl);

  unsigned char *der = nullptr;
  const int len = i2d_X509_CRL(crl.value.get(), &der);
  ASSERT_TRUE(len >= 0); 


  EXPECT_TRUE(utils::equal(data::validDerCrl, der, len));
  OPENSSL_free(der);
}

}}}
