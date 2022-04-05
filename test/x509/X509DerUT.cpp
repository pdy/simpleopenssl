/*
* Copyright (c) 2021 Pawel Drzycimski
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

namespace {

bool equal(const ::so::Bytes &lhs, unsigned char *rhs, int rhsLen)
{
  if(static_cast<int>(lhs.size()) != rhsLen)
    return false;

  size_t idx = 0;
  for(const auto &bt : lhs)
  {
    if(bt != rhs[idx])
      return false;

    ++idx;
  }

  return true;
}

} // namespace

TEST(X509DERUT, certToDerFile)
{
  static constexpr auto TMP_OUT_FILENAME = "data/tmp_der_cert.der";

  const unsigned char *it = data::validDerCert.data();
  auto cert = ::so::make_unique(d2i_X509(nullptr, &it, static_cast<long>(data::validDerCert.size())));
  ASSERT_TRUE(cert);

  auto scope = ::makeScopeGuard([&] { ::removeFile(TMP_OUT_FILENAME); });

  // WHEN
  const auto result = x509::convertX509ToDerFile(*cert, TMP_OUT_FILENAME);

  // THEN
  ASSERT_TRUE(result);
  EXPECT_TRUE(utils::filesEqual("data/validdercert.der", TMP_OUT_FILENAME));
}

TEST(X509DERUT, derFileToCert)
{
  // WHEN
  auto cert = x509::convertDerFileToX509("data/validdercert.der");

  // THEN
  ASSERT_TRUE(cert);

  unsigned char *der = nullptr;
  const int len = i2d_X509(cert.value.get(), &der);
  ASSERT_TRUE(len >= 0); 
  EXPECT_TRUE(equal(data::validDerCert, der, len));
  OPENSSL_free(der);
}

}}}
