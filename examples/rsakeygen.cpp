#include "cmdline/cmdline.h"
#include <simpleopenssl/simpleopenssl.h>

#include <iostream>
#include <iterator>
#include <fstream>

int savePem(RSA &rsa, int keySize);
int saveDer(RSA &key, int keySize);
template<typename DATA>
void saveFile(const std::string &file, const DATA &content);
std::string namePrefix(int keySize);

int main(int argc, char *argv[])
{
  cmdline::parser arg;
  arg.add("help", 'h', "Print help.");
  arg.add<std::string>("format", 'f', "Output keys format [pem, der, all]", false, "pem");
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
  
  const std::string format = arg.get<std::string>("format");
  auto key = maybeKey.moveValue();
  if(format == "der")
    return saveDer(*key, keySize);
  else if(format == "all")
  {
    const auto pemRes = savePem(*key, keySize);
    const auto derRes = saveDer(*key, keySize);
    return pemRes && derRes;
  }
  
  return savePem(*key, keySize); 
}

int savePem(RSA &key, int keySize)
{
  const auto pemPriv = so::rsa::convertPrivKeyToPem(key);
  if(!pemPriv)
  {
    std::cout << "Error converting to PEM: " << pemPriv.msg() << "\n";
    return 0;
  }

  const auto pemPub = so::rsa::convertPubKeyToPem(key);
  if(!pemPub)
  {
    std::cout << "Error converting to PEM: " << pemPub.msg() << "\n";
    return 0;
  }
  
  const std::string privName = namePrefix(keySize) + "_priv.pem";
  const std::string pubName = namePrefix(keySize) + "_pub.pem";
  std::cout << "Generated " << privName << " and " << pubName << "\n";
  saveFile(privName, *pemPriv);
  saveFile(pubName, *pemPub);

  return 0;
}

int saveDer(RSA &key, int keySize)
{
  const auto derPriv = so::rsa::convertPrivKeyToDer(key);
  if(!derPriv)
  {
    std::cout << "Error converting to DER: " << derPriv.msg() << "\n";
    return 0;
  }

  const auto derPub = so::rsa::convertPubKeyToDer(key);
  if(!derPub)
  {
    std::cout << "Error converting to DER: " << derPub.msg() << "\n";
    return 0;
  }
  
  const std::string privName = namePrefix(keySize) + "_priv.der";
  const std::string pubName = namePrefix(keySize) + "_pub.der";
  std::cout << "Generated " << privName << " and " << pubName << "\n";
  saveFile(privName, *derPriv);
  saveFile(pubName, *derPub);

  return 0;
}

template<typename DATA>
void saveFile(const std::string &file, const DATA &content)
{
  std::ofstream outFile(file, std::ios::binary);
  if(!outFile.is_open())
    return;

  outFile.write( reinterpret_cast<const char*>(content.data()), static_cast<std::streamsize>(content.size()));
  outFile.close();
}

std::string namePrefix(int keySize)
{
  return "rsa" + std::to_string(keySize);
}
