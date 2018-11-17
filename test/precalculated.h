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
-----END EC PRIVATE KEY-----)";

// openssl ec -in secp256k1-key.pem -pubout -out public.pem
const static std::string secp256PubKeyPem = R"(-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEOJb9wq5BOGI4rD1fbAkHqc+cgHmDJWTD
q5zmfaSwYoVXisJw72JuYpLCTCkP8FeSbd4CvfFmG9L4n9RBcDE1bA==
-----END PUBLIC KEY-----)";

//openssl genrsa -out private.pem 3072 
const static std::string rsa3072PrivKeyPem = R"(-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----)";

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
-----END PUBLIC KEY-----)";

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

// found in internet...
const static std::string meaninglessInvalidPemCert = R"(-----BEGIN CERTIFICATE-----
MIIHIDCCBgigAwIBAgIIMrM8cLO76sYwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
iftrJvzAOMAPY5b/klZvqH6Ddubg/hUVPkiv4mr5MfWfglCQdFF1EBGNoZSFAU7y
ZkGENAvDmv+5xVCZELeiWA2PoNV4m/SW6NHrF7gz4MwQssqP9dGMbKPOF/D2nxic
TnD5WkGMCWpLgqDWWRoOrt6xf0BPWukQBDMHULlZgXzNtoGlEnwztLlnf0I/WWIS
eBSyDTeFJfopvoqXuws23X486fdKcCAV1n/Nl6y2z+uVvcyTRxY2/jegmV0n0kHf
gfcKzw==
-----END CERTIFICATE-----)";

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
-----END CERTIFICATE-----)";

}}} // namespace so { namespace ut { namespace data {

#endif
