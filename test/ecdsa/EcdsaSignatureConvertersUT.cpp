/*
* Copyright (c) 2018 - 2022 Pawel Drzycimski
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

namespace so { namespace ut { namespace ecdsa {

namespace ecdsa = ::so::ecdsa;

TEST(ecdsa, derSignatureBytesToSignatureStruct)
{
  // GIVEN
  const ecdsa::Signature expected { data::signature_sha256_R, data::signature_sha256_S };

  // WHEN
  auto maybeSig = ecdsa::convertToSignature(data::signature_sha256.data(), data::signature_sha256.size());
  ASSERT_TRUE(maybeSig);
  
  auto sig = maybeSig.moveValue();

  // THEN
  EXPECT_EQ(expected, sig); 
}

TEST(ecdsa, signatureStructToDerBytes)
{
  // GIVEN
  const so::Bytes expected { data::signature_sha256 };
  const ecdsa::Signature sig { data::signature_sha256_R, data::signature_sha256_S };

  // WHEN
  auto maybeDer = ecdsa::convertToDer(sig);
  ASSERT_TRUE(maybeDer);

  auto der = maybeDer.moveValue();

  // THEN
  ASSERT_EQ(expected.size(), der.size());
  EXPECT_TRUE(std::equal(expected.begin(), expected.end(), der.begin()));
}

}}} // namespace so { namespace ut { namespace ecdsa {
