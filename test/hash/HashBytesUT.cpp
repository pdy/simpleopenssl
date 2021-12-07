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


#include <simpleopenssl/simpleopenssl.h>

#include <gtest/gtest.h>

#include <sstream>
#include <functional>

#include "../utils.h"

namespace so { namespace ut { namespace hash {

namespace hash = ::so::hash;

struct HashBytesTestInput
{
  std::string shortDesc;
  std::string fileName;
  std::string expectedHexString;
  std::function<::so::Result<::so::Bytes>(const ::so::Bytes&)> hasher;
};

inline std::ostream& operator<<(std::ostream &s, const HashBytesTestInput &i)
{
  return s << i.shortDesc;
}

class HashBytesUT: public ::testing::TestWithParam<HashBytesTestInput>
{};

TEST_P(HashBytesUT, hash)
{
  // GIVEN
  const auto input { GetParam() };
  const auto data = utils::readBinaryFile(input.fileName); 
  ASSERT_TRUE(!data.empty());

  // WHEN
  const auto btHash = input.hasher(data);

  // THEN
  ASSERT_TRUE(btHash);
  EXPECT_EQ(input.expectedHexString, utils::bin2Hex(btHash.value));
}

const auto hashBytesUTTestCases = ::testing::Values(

    HashBytesTestInput{
      "md4",
      "./data/random_20kB.data",
      "bcf3132f2dc6d4dd3538dec6782790b4",
      [](const ::so::Bytes &bytes) -> ::so::Result<::so::Bytes> {return ::so::hash::md4(bytes);},
    },

  HashBytesTestInput{
      "md5",
      "./data/random_20kB.data",
      "3a230011272f3d219e3999833b8df77a",
      [](const ::so::Bytes &bytes) -> ::so::Result<::so::Bytes> {return ::so::hash::md5(bytes);},
    },

  HashBytesTestInput{
      "sha1",
      "./data/random_20kB.data",
      "7da2e0276dacd60dd9208d8c0c56cfc7560c9140",
      [](const ::so::Bytes &bytes) -> ::so::Result<::so::Bytes> {return ::so::hash::sha1(bytes);},
    },

  HashBytesTestInput{
      "sha224",
      "./data/random_20kB.data",
      "32823f3099a7610848cc3db940f5b477523e42f35b7db280e749cde2",
      [](const ::so::Bytes &bytes) -> ::so::Result<::so::Bytes> {return ::so::hash::sha224(bytes);},
    },

  HashBytesTestInput{
      "sha256",
      "./data/random_20kB.data",
      "c839f5a0a75ddf9191ed73cc1ad30eae966ebde2bc3e27ca8a446a271e47141d",
      [](const ::so::Bytes &bytes) -> ::so::Result<::so::Bytes> {return ::so::hash::sha256(bytes);},
    },

  HashBytesTestInput{
      "sha384",
      "./data/random_20kB.data",
      "50855909d9c6b2c73ebb4f60ca9a66a26bcef06c03777aaa6326e66a606f97c6f3694bae339d57203444435e9fd0a2bb",
      [](const ::so::Bytes &bytes) -> ::so::Result<::so::Bytes> {return ::so::hash::sha384(bytes);},
    },

  HashBytesTestInput{
      "sha512",
      "./data/random_20kB.data",
      "db866b9b1c7b8c2f3419a0a1f3b1f44413480d9ee2b9472fdcf1e6a78ac0a0a71a3a7d742711bfffc30bf015e10f5b551f8d3c22277405d464ab5d50295554d5",
      [](const ::so::Bytes &bytes) -> ::so::Result<::so::Bytes> {return ::so::hash::sha512(bytes);},
    }
);

INSTANTIATE_TEST_SUITE_P(
    Hash,
    HashBytesUT,
    hashBytesUTTestCases 
);

}}}
