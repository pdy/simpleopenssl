#include <simpleopenssl/simpleopenssl.h>
#include "simplelog/simplelog.h"
#include "cmdline/cmdline.h"
#include <iomanip>


using namespace so;

std::string bin2Hex(const so::Bytes &buff);

int main(int argc, char *argv[])
{
  cmdline::parser arg;
  arg.add("help", 'h', "Print help.");
  arg.add<std::string>("file", 'f', "PEM cert file to be printed.", true);
 
  if(!arg.parse(argc, const_cast<const char* const*>(argv)))
  {
    const auto fullErr = arg.error_full();
    if(!fullErr.empty())
      log << fullErr;
     
    log << arg.usage();
    return 0;
  }
  
  if(arg.exist("help"))
  {
    log << arg.usage();
    return 0;
  } 

  if(!arg.exist("file"))
  {
    log << "--file or -f argument is mandatory!";
    log << arg.usage();
    return 0;
  }
  
  //const std::string file = arg.get<std::string>("file");
//  auto maybeX509 = x509::verifySignature

  return 0;
}

std::string bin2Hex(const so::Bytes &buff)
{
  std::ostringstream oss;
  for(const auto bt : buff){
    oss << std::setfill('0') << std::setw(2) << std::hex << +bt;
  }
  return oss.str(); 
}
