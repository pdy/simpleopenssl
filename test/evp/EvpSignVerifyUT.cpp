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

#include <vector>
#include <algorithm>
#include <numeric>
#include <functional>
#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>

#include "../precalculated.h"

namespace so { namespace ut { namespace evp {

namespace evp = ::so::evp;
namespace ecdsa = ::so::ecdsa;

struct EvpSignVerifyInput
{
  std::string shortDesc;
  std::string privKeyPem;
  std::string pubKeyPem;
  ::so::Bytes signedData;
  ::so::Bytes signature;
  std::function<::so::Result<::so::Bytes>(const ::so::Bytes&, EVP_PKEY&)> signer;
  std::function<::so::Result<bool>(const ::so::Bytes&,const ::so::Bytes&, EVP_PKEY&)> verifier;
};

// so that gtest failure log would be more descriptive
std::ostream& operator<<(std::ostream &s, const EvpSignVerifyInput &input)
{
  return s << input.shortDesc;
}

class EvpSignVerifyUT : public ::testing::TestWithParam<EvpSignVerifyInput>
{};

TEST_P(EvpSignVerifyUT, verify_PrecalculatedSignature)
{
  // GIVEN
  const EvpSignVerifyInput input{ GetParam() };
  auto maybeKey = evp::convertPemToPubKey(input.pubKeyPem);
  ASSERT_TRUE(maybeKey);
  auto key = maybeKey.moveValue();

  // WHEN
  const auto verified = input.verifier(input.signature, input.signedData, *key);

  // THEN
  ASSERT_TRUE(verified);
  EXPECT_TRUE(verified.value);
}

TEST_P(EvpSignVerifyUT, signVerify_WithPrecalculatedKey)
{
  // GIVEN
  const EvpSignVerifyInput input{ GetParam() };
  auto maybeKey = evp::convertPemToPrivKey(input.privKeyPem);
  ASSERT_TRUE(maybeKey);
  auto key = maybeKey.moveValue();

  // WHEN
  const auto sig = input.signer(input.signedData, *key); 
  ASSERT_TRUE(sig);
  const auto verified = input.verifier(sig.value, input.signedData, *key);
  ASSERT_TRUE(verified);

  // THEN
  EXPECT_TRUE(verified.value);
}

TEST_P(EvpSignVerifyUT, signVerify_ShouldSignAndVerifyWithEcdsaGeneratedKeys)
{
  // GIVEN
  const EvpSignVerifyInput input{ GetParam() };
  std::vector<uint8_t> data(256);
  std::iota(data.begin(), data.end(), 0); 
  auto key = ecdsa::create(ecdsa::Curve::SECT571R1);
  ASSERT_TRUE(key);

  auto keyUptr = key.moveValue();
  auto maybeEvp = ecdsa::convertToEvp(*keyUptr);
  ASSERT_TRUE(maybeEvp);
  auto evpKey = maybeEvp.moveValue();
  
  // WHEN
  const auto sig = input.signer(data, *evpKey);
  ASSERT_TRUE(sig);
  const auto verResult = input.verifier(sig.value, data, *evpKey);

  // THEN
  ASSERT_TRUE(verResult);
  ASSERT_TRUE(verResult.value);
}

const auto testCases = ::testing::Values(
  EvpSignVerifyInput {
    "Sign/Verify with SHA1",
    data::secp256k1PrivKeyPem,
    data::secp256PubKeyPem,
    data::signedTextBytes,
    data::signature_sha1,
    &::so::evp::signSha1,
    &::so::evp::verifySha1Signature
  },
 
  EvpSignVerifyInput {
    "Sign/Verify with SHA224",
    data::secp256k1PrivKeyPem,
    data::secp256PubKeyPem,
    data::signedTextBytes,
    data::signature_sha224,
    &::so::evp::signSha224,
    &::so::evp::verifySha224Signature
  },

  EvpSignVerifyInput {
    "Sign/Verify with SHA256",
    data::secp256k1PrivKeyPem,
    data::secp256PubKeyPem,
    data::signedTextBytes,
    data::signature_sha256,
    &::so::evp::signSha256,
    &::so::evp::verifySha256Signature
  },

  EvpSignVerifyInput {
    "Sign/Verify with SHA384",
    data::secp256k1PrivKeyPem,
    data::secp256PubKeyPem,
    data::signedTextBytes,
    data::signature_sha384,
    &::so::evp::signSha384,
    &::so::evp::verifySha384Signature
  },
  EvpSignVerifyInput {
    "Sign/Verify with SHA512",
    data::secp256k1PrivKeyPem,
    data::secp256PubKeyPem,
    data::signedTextBytes,
    data::signature_sha512,
    &::so::evp::signSha512,
    &::so::evp::verifySha512Signature
  }
);

INSTANTIATE_TEST_SUITE_P(
    Evp,
    EvpSignVerifyUT,
    testCases 
);

}}}
