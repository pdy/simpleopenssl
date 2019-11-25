#include "cmdline/cmdline.h"
#include <simpleopenssl/simpleopenssl.h>

#include <iostream>
#include <iterator>
#include <fstream>

void saveFile(const std::string &file, const std::string &content);

int main(int argc, char *argv[])
{
  cmdline::parser arg;
  arg.add("help", 'h', "Print help.");
  //arg.add<std::string>("format", 'f', "Output keys format [pem, der]", false, "pem");
  arg.add<int>("key", 'k', "Key size [1024, 2048, 3072, 4096, 5120, 6144, 7168].", false, 3072);
  arg.add<unsigned long>("exponent", 'e', "Exponent value [3, 17, 65537]", false, 65537);
  const std::vector<int> availKeyBits = {1024, 2048, 3072, 4096, 5120, 6144, 7168};  
  const std::vector<unsigned long> availExponents = {3, 17, 65537};  

  if(!arg.parse(argc, const_cast<const char* const*>(argv)))
  {
    const auto fullErr = arg.error_full();
    if(!fullErr.empty())
      std::cout << fullErr << '\n';
     
    std::cout << arg.usage() << '\n';
    return 0;
  }
  
  if(arg.exist("help"))
  {
    std::cout << arg.usage();
    return 0;
  }

  const int keySize = arg.get<int>("key");
  if(std::find(availKeyBits.begin(), availKeyBits.end(), keySize) == availKeyBits.end())
  {
    std::cout << keySize << " is not valid key size. Available values: [";
    std::copy(availKeyBits.begin(), availKeyBits.end(), std::ostream_iterator<int>(std::cout, ", "));
    std::cout << "]\n";
    return 0;
  }
  
  const unsigned long exponent = arg.get<unsigned long>("exponent");
  if(std::find(availExponents.begin(), availExponents.end(), exponent) == availExponents.end())
  {
    std::cout << exponent << " is not valid exponent. Available values: [";
    std::copy(availExponents.begin(), availExponents.end(), std::ostream_iterator<int>(std::cout, ", "));
    std::cout << "]\n";
    return 0;
  }

  auto maybeKey = so::rsa::generateKey(static_cast<so::rsa::KeyBits>(keySize), static_cast<so::rsa::Exponent>(exponent));
  if(!maybeKey)
  {
    std::cout << "Error when generating the key: " << maybeKey.msg() << "\n";
    return 0;
  }

  auto key = maybeKey.moveValue();
  const auto pemPriv = so::rsa::convertPrivKeyToPem(*key);
  if(!pemPriv)
  {
    std::cout << "Error converting to PEM: " << pemPriv.msg() << "\n";
    return 0;
  }

  const auto pemPub = so::rsa::convertPubKeyToPem(*key);
  if(!pemPub)
  {
    std::cout << "Error converting to PEM: " << pemPub.msg() << "\n";
    return 0;
  }
  
  std::cout << "Generated priv.pem and pub.pem with " << keySize << " bits and " << exponent << " exponent\n";
  saveFile("priv.pem", *pemPriv);
  saveFile("pub.pem", *pemPub);

  return 0;
}


void saveFile(const std::string &file, const std::string &content)
{
  std::ofstream outFile(file, std::ios::binary);
  if(!outFile.is_open())
    return;

  outFile.write(content.data(), static_cast<std::streamsize>(content.size()));
  outFile.close();
}
