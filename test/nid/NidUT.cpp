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
#include "../utils.h"
#include "NidsTable.h"
#include <vector>

using namespace so;

namespace {

static std::ostream& operator<<(std::ostream &ss, const NidUTInput &input)
{
  return ss << OBJ_nid2sn(input.rawNid) << " [" << input.rawNid << "]";
}

// std::size from c++17 sooo....
template<typename T, size_t N>
size_t arrSize(const T(&)[N]){ return N; }

}

TEST(NidUT, checkIfEnumValuesAreCorrectlyAssigned)
{
  // I dont want to have value parametrized test here cuase it would generate ~1k test cases
  for(size_t i = 0; i < arrSize(NID_VALIDITY_UT_VALUES); ++i)
    EXPECT_EQ(NID_VALIDITY_UT_VALUES[i].rawNid, static_cast<int>(NID_VALIDITY_UT_VALUES[i].soNid));
}

TEST(NidUT, checkStringName)
{
   
  // I dont want to have value parametrized test here cuase it would generate ~1k test cases
  for(size_t i = 0; i < arrSize(NID_VALIDITY_UT_VALUES); ++i)
  {
    const auto nid = NID_VALIDITY_UT_VALUES[i];
    const char *sn = OBJ_nid2sn(nid.rawNid);
    const char *ln = OBJ_nid2ln(nid.rawNid);

    EXPECT_EQ(nid::getShortName(nid.soNid).value,std::string(sn));
    EXPECT_EQ(nid::getLongName(nid.soNid).value, std::string(ln));
  }
}

