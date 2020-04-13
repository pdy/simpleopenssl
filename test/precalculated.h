#ifndef PDY_SO_PRECALCULATED_H_
#define PDY_SO_PRECALCULATED_H_

#include <string>
#include <vector>
#include <algorithm>

namespace so { namespace ut { namespace data {

const static std::string signedText = "test_test_foobar";
const static std::vector<uint8_t> signedTextBytes = []{
  std::vector<uint8_t> ret;
  ret.reserve(signedText.size());
  std::transform(signedText.begin(), signedText.end(), std::back_inserter(ret),[](char chr){
        return static_cast<uint8_t>(chr);
      });
  return ret;
}();

// openssl ecparam -name secp256k1 -genkey -noout -out secp256k1-key.pem
const static std::string secp256k1PrivKeyPem = R"(-----BEGIN EC PRIVATE KEY-----
MHQCAQEEILN0LpgGaItTy9e/Jxmat+lHS8NgONqTylUVQ8LxhuD1oAcGBSuBBAAK
oUQDQgAEOJb9wq5BOGI4rD1fbAkHqc+cgHmDJWTDq5zmfaSwYoVXisJw72JuYpLC
TCkP8FeSbd4CvfFmG9L4n9RBcDE1bA==
-----END EC PRIVATE KEY-----
)";

// openssl ec -in secp256k1-key.pem -pubout -out public.pem
const static std::string secp256PubKeyPem = R"(-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEOJb9wq5BOGI4rD1fbAkHqc+cgHmDJWTD
q5zmfaSwYoVXisJw72JuYpLCTCkP8FeSbd4CvfFmG9L4n9RBcDE1bA==
-----END PUBLIC KEY-----
)";

// openssl ec -in secp_priv.pem -inform pem -outform der -out secp_key.der
const static std::vector<uint8_t> secp256k1PrivKeyDer = {
  0x30, 0x74, 0x02, 0x01, 0x01, 0x04, 0x20, 0xb3, 0x74, 0x2e, 0x98, 0x06,
  0x68, 0x8b, 0x53, 0xcb, 0xd7, 0xbf, 0x27, 0x19, 0x9a, 0xb7, 0xe9, 0x47,
  0x4b, 0xc3, 0x60, 0x38, 0xda, 0x93, 0xca, 0x55, 0x15, 0x43, 0xc2, 0xf1,
  0x86, 0xe0, 0xf5, 0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a,
  0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x38, 0x96, 0xfd, 0xc2, 0xae, 0x41,
  0x38, 0x62, 0x38, 0xac, 0x3d, 0x5f, 0x6c, 0x09, 0x07, 0xa9, 0xcf, 0x9c,
  0x80, 0x79, 0x83, 0x25, 0x64, 0xc3, 0xab, 0x9c, 0xe6, 0x7d, 0xa4, 0xb0,
  0x62, 0x85, 0x57, 0x8a, 0xc2, 0x70, 0xef, 0x62, 0x6e, 0x62, 0x92, 0xc2,
  0x4c, 0x29, 0x0f, 0xf0, 0x57, 0x92, 0x6d, 0xde, 0x02, 0xbd, 0xf1, 0x66,
  0x1b, 0xd2, 0xf8, 0x9f, 0xd4, 0x41, 0x70, 0x31, 0x35, 0x6c
};

// openssl ec -pubin -in secp_pub.pem -inform pem -outform der -out secp_pub.der
const static std::vector<uint8_t> secp256PubKeyDer = {
  0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
  0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00, 0x04,
  0x38, 0x96, 0xfd, 0xc2, 0xae, 0x41, 0x38, 0x62, 0x38, 0xac, 0x3d, 0x5f,
  0x6c, 0x09, 0x07, 0xa9, 0xcf, 0x9c, 0x80, 0x79, 0x83, 0x25, 0x64, 0xc3,
  0xab, 0x9c, 0xe6, 0x7d, 0xa4, 0xb0, 0x62, 0x85, 0x57, 0x8a, 0xc2, 0x70,
  0xef, 0x62, 0x6e, 0x62, 0x92, 0xc2, 0x4c, 0x29, 0x0f, 0xf0, 0x57, 0x92,
  0x6d, 0xde, 0x02, 0xbd, 0xf1, 0x66, 0x1b, 0xd2, 0xf8, 0x9f, 0xd4, 0x41,
  0x70, 0x31, 0x35, 0x6c
};

//openssl genrsa -out private.pem 3072 
const static std::string rsa3072PrivKeyPem = R"(-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
)";

// openssl rsa -in private.pem -outform PEM -pubout -out public.pem
const static std::string rsa3072PubKeyPem = R"(-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA1kpAu9FYun7qqBfk1vGF
55SnXRDYJtWdODdHT9Tg1SGXMy6RcgFA6FWZeGD++AwPd7+0OVlHtQQmxhn5B2jF
BggSMY3jJNswY4YwIZmFOa1xyzjUjUtE6m8pfT+mWlUR17Qq6mDl0DDbbkPEbVGc
m21nOPIGTRr/Q1dykgFcZ1Bw81YLSjaZ5XVdXRPLc1++EDA4qvf1uLmygwFp2aLI
zOyBniWoAO/jJ8N/acApoBgOKbz4k9WDaffdPPwdBLolGzcbwAn6pQy4j8Rtjurd
H6Fd4hEiApvDfopfNt+UPI4AdPZEBB2slL9h5RZO0M/oVzZ856/jKrqrAE3B6/GG
sHipWmo7WRsR8xRRQgu63uYdMIwFqhHpJvlWFk1GNanqODsxXwhp3IWJWa8OF4DX
wCRhlQSS+6HbgJLr8iXPtNonEgYKW4Fy3UKficPgZKAr4v0q3mAaQO6ySNiJbORP
JOVVJ6VY64Mn+iKgPJaiVcSnLnuzlOGbSvkDu6Y2w9PPAgMBAAE=
-----END PUBLIC KEY-----
)";

// openssl rsa -in private.pem -inform pem -out private.der -outform der
const std::vector<uint8_t> rsa3072PrivKeyDer = {
  0x30, 0x82, 0x06, 0xe4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x81, 0x00,
  0xd6, 0x4a, 0x40, 0xbb, 0xd1, 0x58, 0xba, 0x7e, 0xea, 0xa8, 0x17, 0xe4,
  0xd6, 0xf1, 0x85, 0xe7, 0x94, 0xa7, 0x5d, 0x10, 0xd8, 0x26, 0xd5, 0x9d,
  0x38, 0x37, 0x47, 0x4f, 0xd4, 0xe0, 0xd5, 0x21, 0x97, 0x33, 0x2e, 0x91,
  0x72, 0x01, 0x40, 0xe8, 0x55, 0x99, 0x78, 0x60, 0xfe, 0xf8, 0x0c, 0x0f,
  0x77, 0xbf, 0xb4, 0x39, 0x59, 0x47, 0xb5, 0x04, 0x26, 0xc6, 0x19, 0xf9,
  0x07, 0x68, 0xc5, 0x06, 0x08, 0x12, 0x31, 0x8d, 0xe3, 0x24, 0xdb, 0x30,
  0x63, 0x86, 0x30, 0x21, 0x99, 0x85, 0x39, 0xad, 0x71, 0xcb, 0x38, 0xd4,
  0x8d, 0x4b, 0x44, 0xea, 0x6f, 0x29, 0x7d, 0x3f, 0xa6, 0x5a, 0x55, 0x11,
  0xd7, 0xb4, 0x2a, 0xea, 0x60, 0xe5, 0xd0, 0x30, 0xdb, 0x6e, 0x43, 0xc4,
  0x6d, 0x51, 0x9c, 0x9b, 0x6d, 0x67, 0x38, 0xf2, 0x06, 0x4d, 0x1a, 0xff,
  0x43, 0x57, 0x72, 0x92, 0x01, 0x5c, 0x67, 0x50, 0x70, 0xf3, 0x56, 0x0b,
  0x4a, 0x36, 0x99, 0xe5, 0x75, 0x5d, 0x5d, 0x13, 0xcb, 0x73, 0x5f, 0xbe,
  0x10, 0x30, 0x38, 0xaa, 0xf7, 0xf5, 0xb8, 0xb9, 0xb2, 0x83, 0x01, 0x69,
  0xd9, 0xa2, 0xc8, 0xcc, 0xec, 0x81, 0x9e, 0x25, 0xa8, 0x00, 0xef, 0xe3,
  0x27, 0xc3, 0x7f, 0x69, 0xc0, 0x29, 0xa0, 0x18, 0x0e, 0x29, 0xbc, 0xf8,
  0x93, 0xd5, 0x83, 0x69, 0xf7, 0xdd, 0x3c, 0xfc, 0x1d, 0x04, 0xba, 0x25,
  0x1b, 0x37, 0x1b, 0xc0, 0x09, 0xfa, 0xa5, 0x0c, 0xb8, 0x8f, 0xc4, 0x6d,
  0x8e, 0xea, 0xdd, 0x1f, 0xa1, 0x5d, 0xe2, 0x11, 0x22, 0x02, 0x9b, 0xc3,
  0x7e, 0x8a, 0x5f, 0x36, 0xdf, 0x94, 0x3c, 0x8e, 0x00, 0x74, 0xf6, 0x44,
  0x04, 0x1d, 0xac, 0x94, 0xbf, 0x61, 0xe5, 0x16, 0x4e, 0xd0, 0xcf, 0xe8,
  0x57, 0x36, 0x7c, 0xe7, 0xaf, 0xe3, 0x2a, 0xba, 0xab, 0x00, 0x4d, 0xc1,
  0xeb, 0xf1, 0x86, 0xb0, 0x78, 0xa9, 0x5a, 0x6a, 0x3b, 0x59, 0x1b, 0x11,
  0xf3, 0x14, 0x51, 0x42, 0x0b, 0xba, 0xde, 0xe6, 0x1d, 0x30, 0x8c, 0x05,
  0xaa, 0x11, 0xe9, 0x26, 0xf9, 0x56, 0x16, 0x4d, 0x46, 0x35, 0xa9, 0xea,
  0x38, 0x3b, 0x31, 0x5f, 0x08, 0x69, 0xdc, 0x85, 0x89, 0x59, 0xaf, 0x0e,
  0x17, 0x80, 0xd7, 0xc0, 0x24, 0x61, 0x95, 0x04, 0x92, 0xfb, 0xa1, 0xdb,
  0x80, 0x92, 0xeb, 0xf2, 0x25, 0xcf, 0xb4, 0xda, 0x27, 0x12, 0x06, 0x0a,
  0x5b, 0x81, 0x72, 0xdd, 0x42, 0x9f, 0x89, 0xc3, 0xe0, 0x64, 0xa0, 0x2b,
  0xe2, 0xfd, 0x2a, 0xde, 0x60, 0x1a, 0x40, 0xee, 0xb2, 0x48, 0xd8, 0x89,
  0x6c, 0xe4, 0x4f, 0x24, 0xe5, 0x55, 0x27, 0xa5, 0x58, 0xeb, 0x83, 0x27,
  0xfa, 0x22, 0xa0, 0x3c, 0x96, 0xa2, 0x55, 0xc4, 0xa7, 0x2e, 0x7b, 0xb3,
  0x94, 0xe1, 0x9b, 0x4a, 0xf9, 0x03, 0xbb, 0xa6, 0x36, 0xc3, 0xd3, 0xcf,
  0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x81, 0x00, 0xc3, 0x5b,
  0xb0, 0x46, 0x49, 0xe5, 0x6d, 0x28, 0x35, 0x7f, 0x87, 0x40, 0xfd, 0xdf,
  0xf4, 0x66, 0x9a, 0x74, 0x35, 0xf9, 0x1c, 0x45, 0xd3, 0x2a, 0xe0, 0xcc,
  0x2c, 0x7c, 0x10, 0x23, 0xe4, 0xca, 0x19, 0xd0, 0xf4, 0x5c, 0x6e, 0xa5,
  0xcb, 0xe9, 0xc3, 0xd8, 0x05, 0x11, 0xd0, 0x80, 0x8c, 0x66, 0x31, 0x92,
  0x98, 0x98, 0x4b, 0xd7, 0x7e, 0xa4, 0x49, 0x41, 0x02, 0xfe, 0xb0, 0x0d,
  0x88, 0xc9, 0x25, 0xe4, 0x88, 0x3e, 0xc5, 0x5c, 0x9d, 0x63, 0x30, 0xe8,
  0x6d, 0xca, 0xc3, 0xed, 0xdc, 0x16, 0x4e, 0x8e, 0xa9, 0xc1, 0xc5, 0x0a,
  0x60, 0xca, 0xa5, 0x0b, 0x1a, 0xff, 0x43, 0x06, 0x49, 0x55, 0xd9, 0xe3,
  0x8b, 0xd8, 0x5e, 0xfc, 0x44, 0x5f, 0xb6, 0x3c, 0x81, 0x15, 0x7b, 0x60,
  0x12, 0xb8, 0xf3, 0xf5, 0x4d, 0xc9, 0xff, 0x8a, 0x9d, 0xd9, 0x27, 0x28,
  0x7a, 0xef, 0xb6, 0xc3, 0xea, 0x00, 0x40, 0xe8, 0xe6, 0x81, 0xa6, 0x67,
  0xbe, 0xc7, 0x9c, 0xc6, 0xc0, 0x0b, 0x42, 0xc8, 0x6c, 0xf9, 0x96, 0x42,
  0x8f, 0xf6, 0xf5, 0xd5, 0x93, 0x51, 0xdf, 0xf7, 0x64, 0xfb, 0x7e, 0x08,
  0xd4, 0xad, 0x55, 0xd4, 0x19, 0x3c, 0x55, 0x3c, 0x7d, 0x76, 0x06, 0x93,
  0x48, 0xfe, 0x3c, 0xcc, 0xf6, 0x01, 0xd8, 0x2f, 0x9e, 0xf2, 0xb3, 0xbb,
  0xcc, 0x71, 0x78, 0x21, 0xbe, 0xee, 0x4c, 0xfa, 0x39, 0x43, 0xdc, 0x38,
  0x5f, 0x45, 0x23, 0xb2, 0x9f, 0x5e, 0xa1, 0xa4, 0xd8, 0x6f, 0xb0, 0x1c,
  0x9c, 0x65, 0x74, 0x2c, 0xb4, 0x15, 0x16, 0x30, 0x94, 0xac, 0x2a, 0x98,
  0xf8, 0xbc, 0x48, 0xf5, 0x06, 0xf3, 0x58, 0xf0, 0xd0, 0xdf, 0xee, 0x5a,
  0x0e, 0xab, 0x83, 0x4d, 0x60, 0xff, 0xfa, 0x1c, 0xd8, 0x69, 0x43, 0xb5,
  0x2f, 0xcd, 0x91, 0x92, 0xd4, 0x8d, 0xa7, 0x9a, 0xcf, 0x66, 0x34, 0x60,
  0x33, 0x6a, 0x9b, 0x9d, 0x57, 0x58, 0xc9, 0x49, 0x74, 0xc3, 0xd3, 0x3b,
  0x3c, 0x82, 0x1c, 0xfb, 0x11, 0x26, 0xd0, 0xce, 0xce, 0x96, 0x95, 0x6b,
  0x0f, 0xc1, 0x07, 0x61, 0x50, 0x27, 0xe8, 0x2f, 0xa9, 0xe1, 0x75, 0x58,
  0xc8, 0xce, 0x63, 0xa8, 0xa8, 0x48, 0x99, 0x88, 0xb7, 0xcb, 0x77, 0x0e,
  0x24, 0x62, 0xbb, 0x0d, 0x54, 0xc5, 0xb9, 0x4f, 0x99, 0xc3, 0x96, 0x9e,
  0xe4, 0xec, 0xf4, 0xd1, 0xdb, 0x3a, 0x33, 0xf4, 0xe4, 0x91, 0x2c, 0xca,
  0x6d, 0x05, 0x24, 0xdf, 0x08, 0x2a, 0x37, 0x01, 0xc8, 0x4e, 0x16, 0x2e,
  0x04, 0x9e, 0xc6, 0x64, 0xb6, 0x73, 0x5e, 0x8b, 0x72, 0x7b, 0xf9, 0x92,
  0x44, 0x8f, 0x82, 0x07, 0x03, 0x8a, 0x41, 0xba, 0x7d, 0x05, 0xc7, 0xf2,
  0xb9, 0xb8, 0xcf, 0x8e, 0x44, 0x18, 0x66, 0x47, 0x3a, 0xaa, 0x3e, 0x7d,
  0x69, 0x4a, 0xac, 0x66, 0x40, 0x5a, 0xf5, 0x2d, 0xe9, 0xd9, 0x02, 0x81,
  0xc1, 0x00, 0xff, 0x39, 0xa7, 0xac, 0xad, 0xa3, 0x3c, 0xda, 0xe8, 0xec,
  0x0f, 0x87, 0xa8, 0xbc, 0xdc, 0x8e, 0x20, 0xae, 0x5a, 0xd4, 0x0c, 0x99,
  0xf2, 0xe5, 0x8c, 0x45, 0x62, 0x1e, 0x70, 0xe2, 0xc0, 0xca, 0x37, 0x0a,
  0xbe, 0x82, 0x01, 0x42, 0x2d, 0x80, 0x21, 0xe5, 0x17, 0x1b, 0xfd, 0xb1,
  0x7c, 0x8c, 0xbf, 0x87, 0xad, 0x3c, 0xfa, 0x08, 0xbc, 0x39, 0x55, 0x7b,
  0x35, 0xad, 0x56, 0x72, 0x76, 0x1f, 0x33, 0x27, 0x5b, 0xa5, 0x01, 0xb9,
  0xa1, 0xd3, 0x4b, 0x8a, 0x31, 0x91, 0xa3, 0x1f, 0xd7, 0xa4, 0xbf, 0x41,
  0xbc, 0x70, 0x7a, 0x8a, 0x0e, 0x97, 0xbb, 0x9c, 0x1f, 0xbf, 0x87, 0x11,
  0x2e, 0xc6, 0x6b, 0x70, 0xc9, 0xe9, 0x0d, 0x72, 0x4a, 0xf6, 0x95, 0xfe,
  0x53, 0xfa, 0xe9, 0xe6, 0xe1, 0xb2, 0xf3, 0xd8, 0x22, 0x90, 0xd5, 0xd1,
  0x47, 0xc3, 0xbd, 0x89, 0xcb, 0xee, 0xd2, 0xcb, 0x74, 0x4e, 0x59, 0x10,
  0x5d, 0xd8, 0x8a, 0x3f, 0x77, 0x91, 0xaa, 0x62, 0xf3, 0x8a, 0xf1, 0x34,
  0xe0, 0x65, 0xcf, 0xbc, 0x06, 0x82, 0x01, 0x4f, 0x23, 0x40, 0xb8, 0x9d,
  0xf0, 0x27, 0x8f, 0xd4, 0x17, 0xe0, 0x0f, 0xac, 0x95, 0x58, 0x6a, 0xcf,
  0xab, 0x12, 0x0e, 0xac, 0xf2, 0x9c, 0xfd, 0x0a, 0xb4, 0xf2, 0x28, 0xe8,
  0x8b, 0x11, 0xe8, 0xf1, 0xb7, 0xfb, 0x92, 0x59, 0xc3, 0xa9, 0xf6, 0x03,
  0x89, 0xa3, 0x02, 0x81, 0xc1, 0x00, 0xd6, 0xf0, 0xc9, 0x20, 0x1a, 0x88,
  0x81, 0x67, 0xa4, 0xf9, 0x6e, 0x53, 0x81, 0x2b, 0x8b, 0x7d, 0xf5, 0x22,
  0xaf, 0x05, 0xf4, 0x7f, 0xcc, 0x3b, 0xf8, 0x2b, 0x41, 0xe4, 0xf1, 0xae,
  0x39, 0x21, 0x9c, 0x2d, 0x0d, 0xd4, 0x1a, 0xc8, 0x8d, 0xb2, 0x95, 0xba,
  0x73, 0xba, 0x17, 0xaf, 0xaf, 0x43, 0xcd, 0x9b, 0xcc, 0x32, 0x7f, 0x0a,
  0x8d, 0x8f, 0x13, 0x14, 0x2d, 0xaf, 0x18, 0xc3, 0x00, 0x04, 0x30, 0x1d,
  0x45, 0x13, 0xfb, 0xfe, 0x9c, 0x93, 0x51, 0x07, 0xcf, 0x1a, 0xc7, 0x81,
  0xe3, 0xa5, 0x3a, 0x23, 0xca, 0x37, 0x72, 0xd1, 0xd5, 0x4e, 0x5a, 0x3f,
  0x98, 0xed, 0x52, 0x09, 0xb2, 0x65, 0x2f, 0x1c, 0x84, 0x21, 0x17, 0xee,
  0x81, 0xb1, 0xf9, 0x8d, 0x1c, 0xeb, 0x76, 0xac, 0xc9, 0x4f, 0x95, 0x7e,
  0x58, 0x99, 0x08, 0x6b, 0xce, 0x21, 0x94, 0xb0, 0x9c, 0xea, 0xfb, 0xda,
  0x62, 0xc3, 0x84, 0xb0, 0xa2, 0x7d, 0xc7, 0xa9, 0x61, 0xb2, 0xaf, 0x93,
  0x29, 0xfa, 0xfb, 0x09, 0xc1, 0x4a, 0x84, 0xbf, 0x7f, 0xec, 0x14, 0x88,
  0x58, 0xfb, 0xf7, 0x4c, 0x87, 0x1c, 0xdb, 0x8e, 0xf0, 0xcc, 0x7f, 0xe6,
  0xce, 0x08, 0x67, 0x38, 0xde, 0xb4, 0x52, 0x7c, 0xfc, 0x2f, 0x9f, 0x1d,
  0x70, 0x0a, 0xbe, 0xf5, 0x06, 0xfc, 0xbc, 0x02, 0xb5, 0x19, 0x54, 0x3a,
  0x20, 0x15, 0xd5, 0xb4, 0xc7, 0xe5, 0x02, 0x81, 0xc1, 0x00, 0xd1, 0x74,
  0x67, 0x7e, 0xf7, 0x21, 0x38, 0x18, 0x0f, 0x7f, 0x6b, 0x5f, 0x51, 0xc3,
  0x6c, 0xdd, 0xd7, 0x44, 0x3f, 0x96, 0x36, 0xa1, 0x41, 0x0d, 0xd1, 0x88,
  0x3f, 0x75, 0xeb, 0xfe, 0xab, 0x69, 0x48, 0xb2, 0xb0, 0x95, 0xd0, 0xa2,
  0x96, 0xe4, 0xc8, 0xec, 0x51, 0x82, 0xcf, 0x38, 0x91, 0x96, 0x90, 0xb8,
  0xb0, 0x1b, 0x92, 0xb7, 0x08, 0x81, 0xa4, 0xfd, 0x70, 0x97, 0xc8, 0x92,
  0x37, 0x0e, 0x73, 0xd4, 0xa1, 0x09, 0x51, 0xd9, 0x1e, 0x4d, 0x61, 0x79,
  0x10, 0x25, 0x0d, 0x52, 0x5c, 0x8e, 0xff, 0xc6, 0xda, 0xf7, 0x14, 0x19,
  0xa8, 0xd0, 0x2d, 0x4f, 0x7b, 0x5e, 0x9b, 0x62, 0x26, 0x99, 0x00, 0x23,
  0x98, 0x10, 0x82, 0xd0, 0x81, 0x64, 0xcc, 0xc3, 0xe3, 0xf7, 0xcf, 0x6d,
  0x83, 0x5c, 0x71, 0x71, 0xb7, 0x2c, 0x55, 0xcd, 0x62, 0xaf, 0xe9, 0x24,
  0xe5, 0x10, 0x22, 0x3e, 0x86, 0x3c, 0xa6, 0x2b, 0x20, 0x59, 0x4d, 0x5b,
  0xb8, 0xac, 0xfa, 0xc0, 0x2a, 0x4e, 0xa4, 0x95, 0x58, 0x73, 0x35, 0x80,
  0x81, 0x76, 0xbf, 0xcc, 0x4a, 0x8a, 0x1a, 0xf8, 0xc2, 0xd6, 0x34, 0xdb,
  0x42, 0x9c, 0xc7, 0x40, 0x43, 0x70, 0x44, 0x78, 0x19, 0x54, 0xc0, 0x66,
  0x7e, 0xd5, 0x07, 0x75, 0x79, 0xfa, 0x22, 0x48, 0x75, 0x99, 0x45, 0x2a,
  0xda, 0x6a, 0xc3, 0x38, 0x97, 0xb3, 0x2c, 0x0a, 0xcb, 0x31, 0x02, 0x81,
  0xc0, 0x4b, 0x5d, 0x23, 0xf8, 0x38, 0xb5, 0x72, 0x42, 0x28, 0x0b, 0x39,
  0x4e, 0xd8, 0x34, 0xaf, 0x75, 0x5b, 0xb5, 0x6c, 0x8e, 0xf6, 0xfa, 0xb4,
  0x5e, 0xb6, 0x96, 0x5c, 0x45, 0x6d, 0x24, 0x3c, 0x6d, 0xf7, 0x77, 0xa8,
  0xa8, 0x9d, 0x37, 0x82, 0xcf, 0x82, 0x46, 0x5c, 0xfb, 0x7c, 0x00, 0xa2,
  0xc0, 0x70, 0x60, 0x57, 0x49, 0xc1, 0x57, 0xae, 0xe8, 0xe2, 0xb4, 0xa9,
  0x8c, 0x02, 0x6f, 0xa5, 0x1a, 0xd2, 0xd0, 0x00, 0x7f, 0x90, 0x54, 0xe7,
  0x0b, 0x94, 0x56, 0xdb, 0x9c, 0x35, 0x25, 0xea, 0xee, 0xed, 0x22, 0xcd,
  0x6d, 0x81, 0xb9, 0xe7, 0x43, 0xd0, 0xcb, 0x09, 0xd0, 0xf4, 0x79, 0xe7,
  0xee, 0x28, 0x85, 0xa4, 0x22, 0x82, 0x64, 0xa3, 0x5f, 0x06, 0xf4, 0x1e,
  0x96, 0xc5, 0x06, 0xb2, 0x93, 0x50, 0x04, 0x7c, 0x06, 0x34, 0x78, 0xb0,
  0x4e, 0xff, 0xf6, 0xa9, 0x1e, 0x8f, 0x6e, 0x34, 0x40, 0xff, 0xce, 0x7b,
  0x3b, 0x04, 0xfd, 0xf3, 0xfe, 0x96, 0x27, 0x50, 0x89, 0xea, 0xe9, 0xb1,
  0xb7, 0x72, 0x32, 0x3f, 0x25, 0x44, 0xd1, 0xc5, 0xf9, 0x9a, 0xed, 0x5f,
  0x56, 0x93, 0xf9, 0x5b, 0x9f, 0x28, 0x9d, 0x81, 0xd2, 0x5a, 0x77, 0x0b,
  0x47, 0x48, 0xc1, 0x00, 0x1f, 0xa6, 0x77, 0xc8, 0xe8, 0x4b, 0xaa, 0x58,
  0x67, 0xd7, 0x78, 0x4f, 0x8d, 0x71, 0x05, 0xec, 0x68, 0x1b, 0x85, 0x86,
  0xad, 0x02, 0x81, 0xc0, 0x42, 0xa1, 0xf3, 0xfd, 0xc3, 0x10, 0xac, 0xb3,
  0x60, 0x04, 0x22, 0x68, 0x0b, 0x9b, 0xf4, 0xa7, 0x64, 0x2e, 0xe5, 0x75,
  0xa7, 0x6f, 0x27, 0x82, 0xda, 0xa8, 0xf8, 0x8e, 0xad, 0x99, 0x45, 0x17,
  0x9a, 0x6f, 0xea, 0xb8, 0xce, 0x0c, 0x67, 0x02, 0xbe, 0xbc, 0xd7, 0x6a,
  0x7d, 0xac, 0xf3, 0x8b, 0x0d, 0xda, 0xd9, 0x9c, 0x6f, 0x04, 0x7e, 0x57,
  0x76, 0xa4, 0x6d, 0x4d, 0x81, 0xf6, 0x5d, 0x79, 0xac, 0x71, 0x11, 0x71,
  0x25, 0x27, 0x07, 0xed, 0x95, 0xa0, 0x69, 0xf6, 0x70, 0x79, 0x47, 0xde,
  0xe4, 0x69, 0x65, 0x72, 0xbe, 0x3a, 0x71, 0x3e, 0x6d, 0x50, 0xda, 0xe5,
  0xb5, 0xbb, 0xc8, 0xf8, 0x03, 0x54, 0xbc, 0x4a, 0x6c, 0x96, 0x53, 0x5e,
  0x63, 0x69, 0x1b, 0x02, 0x0f, 0x1e, 0x24, 0x06, 0x6f, 0x14, 0x44, 0x20,
  0xbd, 0xa4, 0x16, 0x2e, 0x2b, 0xd4, 0x05, 0x65, 0x19, 0x2e, 0x41, 0xb3,
  0x03, 0xd5, 0xf4, 0xef, 0x8a, 0xf4, 0xd7, 0x36, 0x9b, 0x81, 0x2b, 0x3b,
  0x1d, 0x5f, 0x5a, 0xac, 0x9f, 0x9a, 0xd1, 0x02, 0xbd, 0x6b, 0x4a, 0x4f,
  0xc1, 0x10, 0xfe, 0x9e, 0x99, 0xd2, 0xf4, 0xbe, 0x2b, 0x1b, 0xfa, 0x85,
  0xce, 0xef, 0x3f, 0x97, 0x39, 0x33, 0xb6, 0x17, 0xc9, 0x3d, 0x5d, 0xa8,
  0xdc, 0xed, 0x96, 0x05, 0x08, 0x43, 0xcf, 0xc2, 0xae, 0xa7, 0x9e, 0x8b,
  0x07, 0xc2, 0x2e, 0xc6
};

// openssl rsa -pubin -inform PEM -in public.pem -outform DER -out public.der
const std::vector<uint8_t> rsa3072PubKeyDer = {
  0x30, 0x82, 0x01, 0xa2, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
  0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x8f, 0x00,
  0x30, 0x82, 0x01, 0x8a, 0x02, 0x82, 0x01, 0x81, 0x00, 0xd6, 0x4a, 0x40,
  0xbb, 0xd1, 0x58, 0xba, 0x7e, 0xea, 0xa8, 0x17, 0xe4, 0xd6, 0xf1, 0x85,
  0xe7, 0x94, 0xa7, 0x5d, 0x10, 0xd8, 0x26, 0xd5, 0x9d, 0x38, 0x37, 0x47,
  0x4f, 0xd4, 0xe0, 0xd5, 0x21, 0x97, 0x33, 0x2e, 0x91, 0x72, 0x01, 0x40,
  0xe8, 0x55, 0x99, 0x78, 0x60, 0xfe, 0xf8, 0x0c, 0x0f, 0x77, 0xbf, 0xb4,
  0x39, 0x59, 0x47, 0xb5, 0x04, 0x26, 0xc6, 0x19, 0xf9, 0x07, 0x68, 0xc5,
  0x06, 0x08, 0x12, 0x31, 0x8d, 0xe3, 0x24, 0xdb, 0x30, 0x63, 0x86, 0x30,
  0x21, 0x99, 0x85, 0x39, 0xad, 0x71, 0xcb, 0x38, 0xd4, 0x8d, 0x4b, 0x44,
  0xea, 0x6f, 0x29, 0x7d, 0x3f, 0xa6, 0x5a, 0x55, 0x11, 0xd7, 0xb4, 0x2a,
  0xea, 0x60, 0xe5, 0xd0, 0x30, 0xdb, 0x6e, 0x43, 0xc4, 0x6d, 0x51, 0x9c,
  0x9b, 0x6d, 0x67, 0x38, 0xf2, 0x06, 0x4d, 0x1a, 0xff, 0x43, 0x57, 0x72,
  0x92, 0x01, 0x5c, 0x67, 0x50, 0x70, 0xf3, 0x56, 0x0b, 0x4a, 0x36, 0x99,
  0xe5, 0x75, 0x5d, 0x5d, 0x13, 0xcb, 0x73, 0x5f, 0xbe, 0x10, 0x30, 0x38,
  0xaa, 0xf7, 0xf5, 0xb8, 0xb9, 0xb2, 0x83, 0x01, 0x69, 0xd9, 0xa2, 0xc8,
  0xcc, 0xec, 0x81, 0x9e, 0x25, 0xa8, 0x00, 0xef, 0xe3, 0x27, 0xc3, 0x7f,
  0x69, 0xc0, 0x29, 0xa0, 0x18, 0x0e, 0x29, 0xbc, 0xf8, 0x93, 0xd5, 0x83,
  0x69, 0xf7, 0xdd, 0x3c, 0xfc, 0x1d, 0x04, 0xba, 0x25, 0x1b, 0x37, 0x1b,
  0xc0, 0x09, 0xfa, 0xa5, 0x0c, 0xb8, 0x8f, 0xc4, 0x6d, 0x8e, 0xea, 0xdd,
  0x1f, 0xa1, 0x5d, 0xe2, 0x11, 0x22, 0x02, 0x9b, 0xc3, 0x7e, 0x8a, 0x5f,
  0x36, 0xdf, 0x94, 0x3c, 0x8e, 0x00, 0x74, 0xf6, 0x44, 0x04, 0x1d, 0xac,
  0x94, 0xbf, 0x61, 0xe5, 0x16, 0x4e, 0xd0, 0xcf, 0xe8, 0x57, 0x36, 0x7c,
  0xe7, 0xaf, 0xe3, 0x2a, 0xba, 0xab, 0x00, 0x4d, 0xc1, 0xeb, 0xf1, 0x86,
  0xb0, 0x78, 0xa9, 0x5a, 0x6a, 0x3b, 0x59, 0x1b, 0x11, 0xf3, 0x14, 0x51,
  0x42, 0x0b, 0xba, 0xde, 0xe6, 0x1d, 0x30, 0x8c, 0x05, 0xaa, 0x11, 0xe9,
  0x26, 0xf9, 0x56, 0x16, 0x4d, 0x46, 0x35, 0xa9, 0xea, 0x38, 0x3b, 0x31,
  0x5f, 0x08, 0x69, 0xdc, 0x85, 0x89, 0x59, 0xaf, 0x0e, 0x17, 0x80, 0xd7,
  0xc0, 0x24, 0x61, 0x95, 0x04, 0x92, 0xfb, 0xa1, 0xdb, 0x80, 0x92, 0xeb,
  0xf2, 0x25, 0xcf, 0xb4, 0xda, 0x27, 0x12, 0x06, 0x0a, 0x5b, 0x81, 0x72,
  0xdd, 0x42, 0x9f, 0x89, 0xc3, 0xe0, 0x64, 0xa0, 0x2b, 0xe2, 0xfd, 0x2a,
  0xde, 0x60, 0x1a, 0x40, 0xee, 0xb2, 0x48, 0xd8, 0x89, 0x6c, 0xe4, 0x4f,
  0x24, 0xe5, 0x55, 0x27, 0xa5, 0x58, 0xeb, 0x83, 0x27, 0xfa, 0x22, 0xa0,
  0x3c, 0x96, 0xa2, 0x55, 0xc4, 0xa7, 0x2e, 0x7b, 0xb3, 0x94, 0xe1, 0x9b,
  0x4a, 0xf9, 0x03, 0xbb, 0xa6, 0x36, 0xc3, 0xd3, 0xcf, 0x02, 0x03, 0x01,
  0x00, 0x01
};

// openssl dgst -sha256 -sign secp256k1-key.pem -out sha256_out.txt test_test_foobar.txt
const static std::vector<uint8_t> signature_sha256 = {
  0x30, 0x46, 0x02, 0x21, 0x00, 0xc8, 0xcb, 0xef, 0xbe, 0x5a, 0x87, 0x97,
  0xdc, 0xdb, 0xea, 0xc1, 0x02, 0x75, 0xf5, 0xbb, 0x42, 0x0a, 0xf6, 0xe5,
  0x2e, 0xce, 0xf0, 0x94, 0x79, 0xdd, 0x77, 0x63, 0x08, 0xec, 0xfe, 0x58,
  0xa8, 0x02, 0x21, 0x00, 0xe4, 0x38, 0xe1, 0x2e, 0x14, 0xce, 0xa8, 0xe5,
  0xb5, 0x6e, 0x4a, 0x9a, 0x87, 0x9c, 0x10, 0xa6, 0x58, 0x3f, 0x40, 0xa4,
  0xf4, 0x25, 0xd5, 0x73, 0x88, 0x4e, 0xe6, 0x3e, 0x88, 0x2f, 0x65, 0x02
};

const static std::vector<uint8_t> signature_sha256_R = {
  0xc8, 0xcb, 0xef, 0xbe, 0x5a, 0x87, 0x97, 0xdc, 0xdb, 0xea, 0xc1, 0x02,
  0x75, 0xf5, 0xbb, 0x42, 0x0a, 0xf6, 0xe5, 0x2e, 0xce, 0xf0, 0x94, 0x79,
  0xdd, 0x77, 0x63, 0x08, 0xec, 0xfe, 0x58, 0xa8
};

const static std::vector<uint8_t> signature_sha256_S = {
  0xe4, 0x38, 0xe1, 0x2e, 0x14, 0xce, 0xa8, 0xe5, 0xb5, 0x6e, 0x4a, 0x9a,
  0x87, 0x9c, 0x10, 0xa6, 0x58, 0x3f, 0x40, 0xa4, 0xf4, 0x25, 0xd5, 0x73,
  0x88, 0x4e, 0xe6, 0x3e, 0x88, 0x2f, 0x65, 0x02
};

// openssl dgst -sha1 -sign secp256k1-key.pem -out sha1_out.txt test_test_foobar.txt
const static std::vector<uint8_t> signature_sha1 = {
  0x30, 0x44, 0x02, 0x20, 0x2b, 0xb8, 0x1f, 0xb4, 0xec, 0x24, 0x2d, 0x52,
  0x19, 0x0b, 0x92, 0x36, 0x4f, 0xf5, 0x6f, 0x0f, 0x5e, 0x0f, 0xee, 0x06,
  0x18, 0x9e, 0x07, 0xdf, 0x2e, 0x4a, 0x51, 0x8d, 0x25, 0x04, 0x73, 0x57,
  0x02, 0x20, 0x0a, 0xf3, 0x24, 0x4f, 0xb9, 0x73, 0x9b, 0x24, 0xf2, 0x06,
  0xcb, 0x60, 0x8d, 0xa5, 0xeb, 0x5d, 0x81, 0xc2, 0x11, 0x4b, 0x1b, 0xc9,
  0x02, 0x3f, 0x70, 0x4b, 0xfd, 0x22, 0x59, 0xa5, 0x0b, 0x22
};

const static std::vector<uint8_t> signature_sha224 = {
  0x30, 0x46, 0x02, 0x21, 0x00, 0xa3, 0x7d, 0x17, 0x37, 0x1d, 0x4b, 0xb0,
  0xe4, 0xfa, 0xef, 0x69, 0xb8, 0xc0, 0x76, 0xf2, 0xbc, 0xf1, 0x59, 0xb2,
  0xea, 0xaa, 0x67, 0xd6, 0xc0, 0xa7, 0x5a, 0xab, 0x94, 0x17, 0xd2, 0x77,
  0x39, 0x02, 0x21, 0x00, 0xf9, 0x2c, 0x8b, 0xf3, 0x93, 0x0e, 0xdf, 0xfc,
  0x3e, 0x94, 0x17, 0xd6, 0x41, 0x01, 0x37, 0xab, 0x10, 0x53, 0x68, 0x51,
  0x6b, 0x3a, 0x73, 0x1a, 0x20, 0x53, 0x36, 0xba, 0x2b, 0xab, 0x04, 0x02
};

const static std::vector<uint8_t> signature_sha384 = {
  0x30, 0x44, 0x02, 0x20, 0x1f, 0xc4, 0x20, 0x84, 0x68, 0xac, 0x81, 0x2f,
  0xbe, 0x6e, 0x38, 0x93, 0x55, 0x8c, 0xda, 0xaf, 0x3f, 0xd6, 0xaa, 0x85,
  0xa0, 0xa1, 0x32, 0x8c, 0xeb, 0xcd, 0xdb, 0xb1, 0x62, 0xe7, 0x64, 0xa5,
  0x02, 0x20, 0x57, 0xd6, 0x77, 0x53, 0x50, 0xea, 0x99, 0x49, 0x6a, 0x74,
  0x32, 0x4e, 0x40, 0x63, 0x47, 0xe3, 0xdf, 0x42, 0x9b, 0xf2, 0xfe, 0x48,
  0x86, 0xac, 0x03, 0x89, 0xc9, 0x6c, 0xc9, 0x21, 0x30, 0xb1
};

const static std::vector<uint8_t> signature_sha512 = {
  0x30, 0x45, 0x02, 0x21, 0x00, 0xe7, 0x61, 0x73, 0xf9, 0x4d, 0x24, 0xc9,
  0x05, 0x4a, 0x89, 0x99, 0x82, 0x65, 0x91, 0xb7, 0xf9, 0xf3, 0xb1, 0xa9,
  0x33, 0xf6, 0xf8, 0x81, 0x60, 0xa3, 0x9f, 0x61, 0x4a, 0x16, 0xf9, 0x66,
  0x98, 0x02, 0x20, 0x41, 0x07, 0xf0, 0x38, 0xbf, 0xbc, 0xaf, 0x8d, 0xbe,
  0x3f, 0xa3, 0x84, 0x7b, 0x76, 0x06, 0xd8, 0x25, 0xcb, 0x6c, 0x56, 0x83,
  0x8f, 0x4c, 0x95, 0xae, 0x1d, 0x2f, 0x64, 0x99, 0xf7, 0x8c, 0xa2
};

// openssl dgst -sha256 -sign rsa_private.pem -out signature_rsa_sha256.txt test_test_foobar.txt
const static std::vector<uint8_t> signature_rsa_sha256 = {
  0x25, 0xfa, 0x87, 0xda, 0xee, 0x30, 0xf8, 0x12, 0x43, 0x31, 0x02, 0x43,
  0x0f, 0xac, 0xe5, 0xe3, 0x04, 0x18, 0xc9, 0xc8, 0x09, 0x3c, 0x86, 0x10,
  0xd1, 0x72, 0xdd, 0x88, 0x34, 0x8c, 0x4a, 0x73, 0xa2, 0x74, 0x5a, 0xc5,
  0x21, 0xa3, 0xe9, 0xb7, 0x9d, 0x5d, 0x7e, 0x48, 0x02, 0x3a, 0x6b, 0x67,
  0x6f, 0x5e, 0xcf, 0x7e, 0xaf, 0xb1, 0xd1, 0xcf, 0x37, 0x72, 0xda, 0x4b,
  0x10, 0x06, 0xb6, 0x03, 0x3b, 0x03, 0x16, 0x85, 0xf3, 0x98, 0x4f, 0xa6,
  0xdf, 0x4e, 0xa4, 0x51, 0x32, 0x25, 0x0a, 0x2c, 0x2c, 0x6e, 0x56, 0x72,
  0xeb, 0x0c, 0x64, 0xd2, 0x10, 0x5f, 0x3c, 0xae, 0x09, 0xc3, 0xa2, 0x43,
  0xad, 0x55, 0xf2, 0xce, 0xa3, 0x3a, 0xd9, 0x51, 0x59, 0xdf, 0x80, 0x32,
  0xe1, 0xc5, 0x20, 0xf1, 0x83, 0xcf, 0x80, 0x5b, 0x33, 0x85, 0x55, 0xe6,
  0x58, 0xf3, 0xce, 0xfb, 0x85, 0x04, 0x3b, 0xc7, 0x5f, 0x69, 0x80, 0x0c,
  0xb5, 0x2a, 0x7c, 0x9d, 0x60, 0x92, 0xa7, 0x67, 0xba, 0x20, 0x6e, 0x61,
  0xde, 0x13, 0xed, 0x46, 0x16, 0x2a, 0x6e, 0xe5, 0x2a, 0x78, 0x1d, 0x3e,
  0x0b, 0x1e, 0x0c, 0xf7, 0x9e, 0x30, 0x14, 0xf5, 0xe4, 0xb0, 0x62, 0xeb,
  0xc2, 0xa5, 0xbd, 0x2b, 0x36, 0xaa, 0x82, 0x02, 0x05, 0x6b, 0x72, 0xc7,
  0x74, 0x01, 0x28, 0xbc, 0x21, 0x0b, 0x2f, 0xb5, 0x26, 0xd1, 0x05, 0x5c,
  0x62, 0xad, 0x3a, 0xea, 0x57, 0xb2, 0x6a, 0x8d, 0xd9, 0x83, 0xfb, 0xed,
  0x7a, 0xd3, 0x5f, 0x0f, 0x1e, 0xfb, 0xd8, 0xfb, 0xf5, 0x84, 0x78, 0x70,
  0x0c, 0x35, 0xa5, 0x1b, 0x29, 0x9e, 0x61, 0x90, 0x6a, 0x04, 0x52, 0xb4,
  0x4a, 0xc8, 0x9d, 0x04, 0xa3, 0xf1, 0x73, 0x7b, 0x2d, 0x85, 0xf9, 0x67,
  0x8e, 0xcf, 0xf3, 0x9f, 0x61, 0xb8, 0xa8, 0xc1, 0x8e, 0xc1, 0xbf, 0xe6,
  0x84, 0x54, 0xf2, 0xd3, 0x67, 0x37, 0x9c, 0x07, 0x16, 0xbd, 0xf1, 0x35,
  0xf9, 0x69, 0xd0, 0x88, 0xca, 0x06, 0x26, 0xd4, 0x39, 0x9f, 0xd1, 0xdd,
  0x20, 0xcc, 0x39, 0x02, 0xcd, 0xc6, 0x48, 0x37, 0x13, 0xc5, 0x1e, 0xed,
  0xbd, 0xa3, 0xd4, 0x10, 0x6e, 0xff, 0x2d, 0xfb, 0x1f, 0x4d, 0x28, 0x63,
  0x98, 0xd4, 0x3a, 0x7c, 0x23, 0x41, 0x5f, 0x69, 0x57, 0x04, 0xf9, 0x98,
  0x3f, 0xab, 0x21, 0x4d, 0x9e, 0x26, 0xd2, 0x3f, 0xe5, 0x3e, 0x28, 0xb1,
  0x2a, 0xc9, 0x6a, 0x52, 0xac, 0x75, 0xdd, 0x96, 0x20, 0x87, 0x85, 0x58,
  0x28, 0xa9, 0x0a, 0x37, 0x38, 0xb3, 0x5c, 0x6b, 0xe8, 0xc3, 0x2b, 0x5a,
  0xee, 0x0d, 0xee, 0xce, 0xee, 0x3f, 0x2a, 0x67, 0x1c, 0x67, 0x63, 0x9a,
  0x00, 0x26, 0x5f, 0xf3, 0x0d, 0x40, 0xd6, 0x0e, 0x6b, 0xb4, 0x93, 0xd3,
  0x22, 0xd5, 0x77, 0x9a, 0xc7, 0xc1, 0x37, 0x1d, 0x31, 0x66, 0xb9, 0x42
};


// openssl dgst -sha1 -sign rsa_private.pem -out signature_rsa_sha1.txt test_test_foobar.txt
static const std::vector<uint8_t> signature_rsa_sha1 = {
  0x91, 0xe1, 0x72, 0xda, 0x77, 0x82, 0x6d, 0x40, 0x10, 0xc2, 0xc0, 0xa5,
  0x8f, 0x32, 0x78, 0x30, 0x37, 0x37, 0x1f, 0xab, 0x84, 0x70, 0x47, 0xac,
  0xab, 0xfd, 0x4b, 0xe9, 0x70, 0x65, 0x04, 0xe0, 0xfb, 0x41, 0x3e, 0x69,
  0x05, 0xe5, 0xa5, 0x96, 0xb1, 0x47, 0x11, 0xb8, 0x6a, 0xc5, 0x11, 0x38,
  0x56, 0xe7, 0x27, 0xf3, 0x2e, 0x96, 0x3c, 0x3a, 0x36, 0x44, 0xf1, 0x54,
  0xcd, 0x89, 0x7a, 0x8a, 0x55, 0x68, 0xea, 0x77, 0x35, 0x32, 0x9e, 0x6b,
  0xaf, 0x1b, 0xfc, 0xd4, 0xe9, 0xcc, 0xc3, 0x37, 0xc9, 0x66, 0xda, 0x3a,
  0x02, 0x12, 0xcf, 0x3c, 0x9c, 0x3f, 0x45, 0x2b, 0x0a, 0x32, 0x50, 0xc8,
  0x16, 0xfd, 0x40, 0xc2, 0x58, 0x67, 0x5c, 0xf7, 0x75, 0xea, 0xf5, 0x28,
  0x15, 0xd6, 0xf7, 0x2e, 0xe4, 0x91, 0x25, 0xa6, 0x78, 0xc1, 0x05, 0x96,
  0x2b, 0x2a, 0xbb, 0x8e, 0x5a, 0x5b, 0x0c, 0xc8, 0x2c, 0x6e, 0x00, 0xba,
  0x21, 0xff, 0x21, 0x39, 0x5e, 0x89, 0xef, 0x75, 0x6d, 0xa6, 0x6f, 0x2b,
  0x64, 0x29, 0x47, 0x3c, 0x95, 0x7f, 0xca, 0x4b, 0x3a, 0xe6, 0xe0, 0x49,
  0xae, 0xdb, 0x79, 0x45, 0xdf, 0x05, 0xc5, 0xa0, 0xa8, 0xea, 0x85, 0xa0,
  0xb2, 0x78, 0xe5, 0xe6, 0xd8, 0x3e, 0x44, 0x4c, 0x14, 0x6f, 0x43, 0x56,
  0x26, 0x65, 0x64, 0xfb, 0x31, 0xb8, 0xd4, 0x5f, 0x26, 0xde, 0xea, 0xf4,
  0x5e, 0x02, 0x44, 0x48, 0xd6, 0x29, 0xef, 0x55, 0x98, 0xde, 0xbb, 0x80,
  0x2c, 0x0d, 0x1e, 0xe9, 0x66, 0xd6, 0x92, 0xd9, 0xb5, 0x93, 0x10, 0x82,
  0x56, 0x03, 0x7c, 0x2f, 0x36, 0xdb, 0x58, 0xb2, 0x6e, 0x03, 0x6a, 0x6f,
  0x74, 0xdf, 0xfd, 0x83, 0x0c, 0x5e, 0xe7, 0x69, 0x7e, 0x0f, 0x4a, 0x78,
  0xa9, 0x17, 0x02, 0xd6, 0x55, 0xc1, 0xb1, 0x0d, 0xbd, 0x3e, 0xb6, 0x44,
  0x93, 0x9e, 0x91, 0xad, 0x8d, 0xa4, 0x00, 0x99, 0x47, 0x20, 0xa3, 0xce,
  0x94, 0xea, 0x11, 0x39, 0x26, 0xde, 0x7f, 0x60, 0x20, 0x3c, 0xf2, 0x95,
  0xad, 0xdb, 0xd6, 0x48, 0x27, 0xc3, 0x27, 0xb0, 0xc4, 0xf0, 0x05, 0xa3,
  0x53, 0x90, 0x51, 0x5d, 0xac, 0x00, 0x31, 0x00, 0xf3, 0x7d, 0x29, 0x89,
  0x23, 0x08, 0x1d, 0xf8, 0xfb, 0xf5, 0xfc, 0x5f, 0x9a, 0x9d, 0xee, 0x87,
  0xd3, 0xeb, 0x27, 0x33, 0x96, 0xed, 0x30, 0x8f, 0x8e, 0xdc, 0x36, 0xed,
  0xd6, 0x01, 0x15, 0x29, 0x96, 0x0f, 0x9c, 0xb8, 0xb0, 0xb1, 0xdb, 0x96,
  0xc3, 0xea, 0x9b, 0xb5, 0x3d, 0xcd, 0xc2, 0x95, 0x23, 0x76, 0x0d, 0x2b,
  0x03, 0x26, 0x04, 0xc5, 0xbd, 0x5b, 0xf4, 0xec, 0x51, 0x19, 0xf3, 0x02,
  0x25, 0x3b, 0x8c, 0x02, 0x03, 0x98, 0xb2, 0xb2, 0x59, 0x17, 0x6e, 0x05,
  0x38, 0x7f, 0x59, 0xba, 0x0a, 0xd3, 0x1a, 0x10, 0x1c, 0x76, 0xad, 0x96
};

// openssl dgst -sha224 -sign rsa_private.pem -out signature_rsa_sha224.txt test_test_foobar.txt
static const std::vector<uint8_t> signature_rsa_sha224 = {
  0x8a, 0xd5, 0x89, 0x8d, 0xb9, 0x8e, 0x52, 0x04, 0xd9, 0x81, 0x71, 0x26,
  0x66, 0x3c, 0xf1, 0xe6, 0x30, 0x06, 0xe5, 0xb7, 0x32, 0xf1, 0x0c, 0x83,
  0x93, 0xe0, 0xa3, 0xf5, 0xac, 0x40, 0x89, 0x07, 0x2e, 0x6c, 0xd1, 0x51,
  0xfb, 0xb2, 0xef, 0xef, 0xec, 0x42, 0x91, 0xa4, 0x9b, 0xa2, 0x36, 0x29,
  0x1f, 0xf6, 0x1b, 0x5c, 0xa2, 0xf0, 0x48, 0xc0, 0x23, 0x9f, 0x70, 0x5d,
  0x6d, 0x5a, 0x87, 0x35, 0x37, 0x4c, 0x99, 0xb4, 0xef, 0xbf, 0x8e, 0x5d,
  0xdf, 0x60, 0x14, 0xd1, 0x2d, 0x19, 0x0f, 0xb3, 0x1b, 0xac, 0x7d, 0x9f,
  0x73, 0xc2, 0xb8, 0x9c, 0x92, 0x2e, 0xb1, 0x68, 0x3f, 0xa9, 0xc2, 0x7f,
  0xb7, 0x33, 0x1d, 0x63, 0x04, 0xac, 0x90, 0x19, 0x35, 0xfc, 0x2a, 0x5b,
  0x7c, 0xb9, 0x6e, 0x55, 0xf1, 0x9b, 0x47, 0x5f, 0xd1, 0x46, 0xaa, 0x04,
  0x3a, 0x84, 0x6c, 0xe7, 0x88, 0xe3, 0x3a, 0xf5, 0x86, 0x75, 0xfa, 0x1f,
  0x0d, 0xb9, 0xbb, 0xd9, 0xf1, 0x20, 0x48, 0xa8, 0x87, 0x43, 0xf8, 0x1f,
  0x8f, 0x1c, 0xa6, 0xae, 0x4c, 0x51, 0xc8, 0xd0, 0x8f, 0x1e, 0x24, 0xd4,
  0x7d, 0x72, 0x76, 0x4e, 0x71, 0x30, 0xd6, 0x5a, 0x4e, 0x42, 0x56, 0x14,
  0xe2, 0x26, 0x46, 0xf7, 0xc7, 0x6f, 0x88, 0x70, 0x40, 0xd0, 0x55, 0x06,
  0x7a, 0xd9, 0x63, 0x4a, 0x5f, 0x0b, 0xd2, 0x85, 0x70, 0x49, 0x81, 0x0b,
  0xcc, 0x53, 0xbf, 0xaa, 0x0f, 0xe1, 0xa7, 0xf6, 0x58, 0x20, 0x91, 0xcc,
  0x59, 0x63, 0x6f, 0x80, 0x4c, 0x12, 0xbb, 0x89, 0xf3, 0xf6, 0xe0, 0xa0,
  0x9e, 0x5d, 0x37, 0xbd, 0xa7, 0xc3, 0xcb, 0xe3, 0xc6, 0xb8, 0x0a, 0xf3,
  0xa6, 0x48, 0xff, 0xb5, 0xb7, 0xb2, 0x13, 0xed, 0xc6, 0x19, 0xf9, 0x54,
  0xd8, 0x55, 0xfa, 0x77, 0x8b, 0x17, 0x06, 0xe7, 0x3f, 0x25, 0xdc, 0x0b,
  0xf7, 0xc6, 0x02, 0xbe, 0x44, 0xf2, 0x5d, 0x72, 0x59, 0x47, 0xe2, 0x9b,
  0x3e, 0x4a, 0x3c, 0x61, 0x6d, 0x65, 0x6f, 0xae, 0x3b, 0x1c, 0xe6, 0x9a,
  0xe8, 0x77, 0xf7, 0xf7, 0x0e, 0x45, 0xf0, 0xfb, 0xf3, 0x39, 0xd2, 0xa5,
  0x8a, 0x37, 0x0e, 0x2a, 0x0b, 0x4f, 0xf5, 0xb7, 0x7f, 0xc1, 0x7c, 0x3f,
  0x5e, 0xb0, 0x68, 0x0a, 0x1b, 0x11, 0x16, 0xfa, 0x96, 0xf0, 0x32, 0x12,
  0xf6, 0xc3, 0xee, 0x6f, 0x1f, 0xb9, 0x56, 0x05, 0xa2, 0xa6, 0x80, 0x9b,
  0x97, 0x6a, 0xd9, 0x45, 0x99, 0x25, 0x79, 0xa2, 0x94, 0xff, 0x48, 0x13,
  0xdc, 0x92, 0x1c, 0x0e, 0xd8, 0x69, 0x43, 0xdc, 0x9a, 0xcd, 0xf4, 0x23,
  0x27, 0x6a, 0x28, 0x31, 0x26, 0x5c, 0xab, 0x90, 0x32, 0xdf, 0xcd, 0x4e,
  0xaf, 0xde, 0x88, 0x99, 0x2c, 0x89, 0x6a, 0xd7, 0x09, 0x8e, 0xb0, 0xdc,
  0x23, 0xb1, 0xfa, 0x69, 0x79, 0xc8, 0xc7, 0x57, 0x53, 0x26, 0x91, 0x2b
};

// openssl dgst -sha384 -sign rsa_private.pem -out signature_rsa_sha384.txt test_test_foobar.txt
static const std::vector<uint8_t> signature_rsa_sha384 = {
  0x18, 0x33, 0x2f, 0x56, 0x29, 0x6c, 0xae, 0xb4, 0x0c, 0x20, 0xc2, 0x97,
  0xc1, 0x92, 0x0b, 0x9a, 0x35, 0x96, 0x57, 0xb4, 0x04, 0xcf, 0x59, 0x05,
  0x54, 0x08, 0x67, 0x3a, 0x53, 0x3f, 0x5c, 0xa7, 0x77, 0x8e, 0xed, 0xea,
  0x0d, 0xfb, 0xb1, 0x74, 0x9d, 0xfa, 0x90, 0x6b, 0x02, 0x9c, 0x29, 0xbe,
  0x96, 0x8f, 0x1b, 0xcd, 0x02, 0x42, 0x16, 0xce, 0xe6, 0x8b, 0x21, 0xf3,
  0x60, 0xe3, 0x43, 0xb3, 0xed, 0x62, 0x7d, 0xa7, 0x93, 0xe8, 0x32, 0x5d,
  0x01, 0xbe, 0xd8, 0x9d, 0xd6, 0xef, 0x3c, 0x30, 0xf0, 0x98, 0xbd, 0x9e,
  0x7a, 0x06, 0x26, 0xa9, 0xab, 0xef, 0x46, 0x33, 0x9a, 0x3e, 0x24, 0x20,
  0xb1, 0x84, 0x08, 0x33, 0xad, 0xcb, 0xd4, 0x35, 0x8f, 0x47, 0x2d, 0x62,
  0x10, 0xfa, 0xce, 0x42, 0xc4, 0xf4, 0x99, 0x9f, 0xb0, 0x0d, 0x9b, 0x44,
  0xce, 0x86, 0x4f, 0xe1, 0x06, 0x24, 0x07, 0x3a, 0x88, 0x2a, 0xc6, 0x5b,
  0xd2, 0xe5, 0xbe, 0x01, 0x10, 0xd0, 0x3e, 0xe4, 0x25, 0xcf, 0x83, 0x95,
  0x5f, 0x23, 0x0d, 0xb9, 0x03, 0x1a, 0xb1, 0x6a, 0x41, 0xcc, 0x42, 0x14,
  0x0e, 0x5e, 0xd5, 0x6b, 0x44, 0x80, 0x28, 0x5b, 0x04, 0xda, 0x0a, 0x27,
  0x24, 0x1e, 0xb2, 0xd8, 0x4e, 0x6b, 0x46, 0xc2, 0x36, 0xe5, 0xcc, 0x80,
  0x8b, 0x1a, 0x7f, 0xd3, 0x0f, 0xe7, 0xf8, 0x51, 0x2f, 0xdf, 0xf2, 0x64,
  0x46, 0xfc, 0xbd, 0xc4, 0x07, 0x90, 0xf0, 0x69, 0x29, 0xe3, 0xac, 0xd9,
  0x82, 0x3f, 0x97, 0x83, 0x12, 0x48, 0x75, 0xb9, 0x97, 0x86, 0x11, 0x34,
  0x61, 0xf0, 0xb8, 0x99, 0x57, 0x4c, 0x66, 0x7d, 0x10, 0x3a, 0xd3, 0xe1,
  0x61, 0x37, 0x93, 0x6b, 0x74, 0x60, 0x52, 0xb3, 0x3e, 0x35, 0xfe, 0xf4,
  0x35, 0x0a, 0x87, 0x5b, 0x3d, 0x59, 0xff, 0x00, 0xf4, 0x15, 0x4d, 0xf8,
  0x22, 0x29, 0x73, 0x8b, 0x79, 0x04, 0x9f, 0x0a, 0x71, 0x6e, 0x58, 0xc8,
  0x87, 0xcf, 0xd4, 0x44, 0x50, 0xd5, 0x04, 0x69, 0x93, 0x94, 0x15, 0xd3,
  0xf4, 0xfc, 0x55, 0x00, 0x3f, 0x4e, 0xd7, 0xf1, 0x14, 0x65, 0xd6, 0xe8,
  0x4b, 0x2d, 0xa4, 0x2a, 0xd5, 0x82, 0xab, 0xb8, 0xbd, 0xa1, 0x86, 0x1e,
  0x80, 0x32, 0x0c, 0x7e, 0x54, 0xf8, 0xb8, 0x63, 0x0f, 0x35, 0x4d, 0x65,
  0xae, 0xaf, 0x26, 0x57, 0x3a, 0x3c, 0xcc, 0x07, 0x18, 0xd7, 0x7a, 0x39,
  0xab, 0x99, 0xcc, 0x1f, 0x71, 0x8b, 0x5f, 0x10, 0x1e, 0x58, 0x4d, 0xfa,
  0xb1, 0x38, 0x38, 0xa1, 0x48, 0x34, 0x9d, 0x61, 0xc7, 0x22, 0xd8, 0x5d,
  0xd3, 0x9b, 0x4f, 0xf7, 0x18, 0x43, 0x89, 0xd8, 0x78, 0x7d, 0x6f, 0x9c,
  0x65, 0x62, 0x9d, 0xed, 0xf0, 0xf6, 0x72, 0x5e, 0x6b, 0x42, 0xdf, 0x76,
  0x87, 0xf0, 0x6b, 0x53, 0x36, 0x27, 0x08, 0xc4, 0xb1, 0xcf, 0x09, 0xeb
};


// openssl dgst -sha512 -sign rsa_private.pem -out signature_rsa_sha512.txt test_test_foobar.txt
static const std::vector<uint8_t> signature_rsa_sha512 = {
  0x59, 0x86, 0x6d, 0xea, 0x80, 0xb0, 0xb5, 0xb9, 0x56, 0x90, 0x10, 0xea,
  0x4c, 0xda, 0x00, 0x81, 0xef, 0xcd, 0xf1, 0x37, 0x15, 0xe0, 0x94, 0xb0,
  0x02, 0x8d, 0x77, 0x96, 0xa9, 0xf3, 0x01, 0x8a, 0x3a, 0xc6, 0xeb, 0x09,
  0x4b, 0xf8, 0xd9, 0x9e, 0x19, 0x1d, 0x80, 0x7c, 0xc2, 0xb5, 0x8b, 0xe1,
  0xfd, 0xe5, 0xf3, 0x0f, 0x6f, 0x2b, 0x79, 0xa2, 0xaa, 0x9e, 0x16, 0xdb,
  0x3a, 0xb3, 0x66, 0x41, 0x73, 0x76, 0xd6, 0xf1, 0x41, 0x5b, 0x3f, 0x40,
  0x55, 0x10, 0x4c, 0xa7, 0xed, 0x17, 0x00, 0x62, 0xf7, 0x2b, 0xa8, 0x58,
  0x6a, 0xbd, 0x9b, 0xdc, 0x13, 0xf0, 0x1c, 0x72, 0x51, 0x8e, 0xe7, 0x41,
  0x00, 0x2f, 0x52, 0x00, 0x01, 0xa2, 0x94, 0xae, 0x98, 0x92, 0x1b, 0x9a,
  0x56, 0x24, 0xec, 0xa2, 0xc1, 0x28, 0xa3, 0x46, 0xfa, 0x98, 0xea, 0x03,
  0x5b, 0xdb, 0xbf, 0x0e, 0xb7, 0x1f, 0x65, 0x6a, 0x8f, 0xeb, 0xbe, 0xae,
  0x51, 0x07, 0x60, 0x83, 0xfd, 0xd8, 0x61, 0x01, 0xbc, 0xec, 0xbc, 0xfb,
  0xa5, 0x36, 0x86, 0x88, 0xd9, 0x9d, 0xb0, 0x83, 0x69, 0x03, 0x3a, 0x72,
  0x9e, 0xdf, 0x04, 0x4d, 0xdf, 0xaa, 0x4f, 0x44, 0x6c, 0x34, 0xdd, 0xe9,
  0x48, 0xbb, 0xee, 0x65, 0x9b, 0x27, 0xf9, 0x23, 0xe0, 0xb5, 0xb8, 0x82,
  0x66, 0x39, 0xda, 0x0f, 0x28, 0x8d, 0xab, 0xcc, 0xee, 0x5e, 0xa7, 0x2b,
  0xc8, 0x9c, 0x78, 0x84, 0x9f, 0x33, 0x47, 0xcd, 0xac, 0xad, 0x0c, 0x60,
  0xd1, 0x0a, 0x9c, 0x6a, 0x77, 0x3c, 0x8d, 0x75, 0x79, 0x36, 0x2c, 0x09,
  0x2b, 0x35, 0x97, 0x41, 0xa4, 0x50, 0x8c, 0x9b, 0x10, 0xab, 0x34, 0xab,
  0xf4, 0x31, 0x2f, 0xe3, 0xf4, 0x2a, 0x68, 0x75, 0x19, 0x76, 0x26, 0x2a,
  0x72, 0xb7, 0x22, 0xaf, 0xf6, 0x53, 0xb0, 0x3b, 0xd6, 0x91, 0xb0, 0x2d,
  0xd1, 0xd3, 0xff, 0x0c, 0x0a, 0x98, 0x8b, 0x77, 0x7b, 0x4a, 0x1b, 0x4f,
  0x9f, 0x28, 0x3f, 0x6a, 0xdb, 0xff, 0x32, 0x4c, 0x4f, 0x9f, 0x94, 0x0c,
  0xbb, 0xc0, 0xcf, 0x39, 0x0c, 0x24, 0xdc, 0x31, 0x42, 0x97, 0x4c, 0xa3,
  0xf1, 0x5a, 0xa7, 0xff, 0xcb, 0xf0, 0xbe, 0xca, 0x81, 0xe5, 0xd0, 0x0c,
  0xde, 0xe1, 0x16, 0x64, 0x6f, 0x37, 0x53, 0x0c, 0xfa, 0x16, 0x9e, 0xde,
  0xca, 0x38, 0xa5, 0x8a, 0x6e, 0x05, 0x0f, 0x5a, 0xa7, 0xb8, 0xd0, 0x41,
  0xfb, 0xd3, 0x26, 0x3c, 0xeb, 0x0a, 0xd8, 0x40, 0x2c, 0x37, 0x68, 0x06,
  0x5e, 0x31, 0xdc, 0x78, 0xe3, 0x9b, 0x7f, 0x53, 0x04, 0xe4, 0x3e, 0xf1,
  0xec, 0xd9, 0xae, 0xad, 0xa1, 0x93, 0x5e, 0xe6, 0xf4, 0x5f, 0x27, 0x0a,
  0xca, 0x41, 0xe1, 0xe3, 0x0c, 0xdf, 0xd5, 0x55, 0xeb, 0x69, 0xca, 0xec,
  0x9a, 0xb7, 0xc8, 0xb8, 0x7c, 0x83, 0x1a, 0x1e, 0xf6, 0x1c, 0x42, 0xc8
};

// found in internet...
const static std::string meaninglessInvalidPemCert = R"(-----BEGIN CERTIFICATE-----
MIIHIDCCBgigAwIBAgIIMrM8cLO76sYwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
iftrJvzAOMAPY5b/klZvqH6Ddubg/hUVPkiv4mr5MfWfglCQdFF1EBGNoZSFAU7y
ZkGENAvDmv+5xVCZELeiWA2PoNV4m/SW6NHrF7gz4MwQssqP9dGMbKPOF/D2nxic
TnD5WkGMCWpLgqDWWRoOrt6xf0BPWukQBDMHULlZgXzNtoGlEnwztLlnf0I/WWIS
eBSyDTeFJfopvoqXuws23X486fdKcCAV1n/Nl6y2z+uVvcyTRxY2/jegmV0n0kHf
gfcKzw==
-----END CERTIFICATE-----
)";

const static std::string meaninglessValidPemCert = R"(-----BEGIN CERTIFICATE-----
MIICiTCCAg+gAwIBAgIQH0evqmIAcFBUTAGem2OZKjAKBggqhkjOPQQDAzCBhTEL
MAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
BxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMT
IkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMDgwMzA2MDAw
MDAwWhcNMzgwMTE4MjM1OTU5WjCBhTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdy
ZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09N
T0RPIENBIExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBFQ0MgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQDR3svdcmCFYX7deSR
FtSrYpn1PlILBs5BAH+X4QokPB0BBO490o0JlwzgdeT6+3eKKvUDYEs2ixYjFq0J
cfRK9ChQtP6IHG4/bC8vCVlbpVsLM5niwz2J+Wos77LTBumjQjBAMB0GA1UdDgQW
BBR1cacZSBm8nZ3qQUfflMRId5nTeTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAwNoADBlAjEA7wNbeqy3eApyt4jf/7VGFAkK+qDm
fQjGGoe9GKhzvSbKYAydzpmfz1wPMOG+FDHqAjAU9JM8SaczepBGR7NjfRObTrdv
GDeAU/7dIOA1mjbRxwG55tzd8/8dLDoWV9mSOdY=
-----END CERTIFICATE-----
)";

}}} // namespace so { namespace ut { namespace data {

#endif
