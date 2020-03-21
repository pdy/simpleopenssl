#include "cmdline/cmdline.h"
#include "simplelog/simplelog.h"
#include <stdexcept>

#include <fstream>

template<typename T>
struct CloseStream
{
  CloseStream(T &_stream) : stream(_stream) {}
  ~CloseStream() {stream.close();}

  T &stream;
};


std::string formTestSecion(const std::string &nidLine);
std::string formSoEntry(const std::string &nidLine);

int main(int argc, char *argv[])
{
  cmdline::parser arg;
  arg.add("help", 'h', "Print help.");
  arg.add<std::string>("file", 'f', "Path to obj_mac.h", true);
    
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
    log << "--file or -f argument is mandatory!\n";
    log << arg.usage();
    return 0;
  }

  const std::string file = arg.get<std::string>("file");
  std::ifstream in(file); 
  if(!in.is_open())
  {
    log << "Can't open " << file;
    return 0;
  }
  const CloseStream<decltype(in)> inGuard(in);
  
  const std::string testsOutFile = "./nidstestcases.txt";
  std::ofstream testsOut(testsOutFile);
  if(!testsOut.is_open())
  {
    log << "Can't open " << testsOutFile;
    return 0;
  }
  const CloseStream<decltype(testsOut)> testsOutGuard(testsOut);

  const std::string soOutFile = "./sonamespace.txt";
  std::ofstream soOut(soOutFile);
  if(!testsOut.is_open())
  {
    log << "Can't open " << soOutFile;
    return 0;
  }
  const CloseStream<decltype(soOut)> soOutGuard(soOut);

  log << "Writing to " << testsOutFile;
  log << "Writing to " << soOutFile;

  testsOut << "const static NidUTInput NID_VALIDITY_UT_VALUES[] {\n";
  size_t nidsWritten = 0;
  for(std::string line; std::getline(in, line);)
  {
    if(line.find("NID_") != std::string::npos)
    {
      try {
        testsOut << formTestSecion(line);
        soOut << formSoEntry(line);
      }catch(const std::runtime_error &e){
        log << e.what();
        throw;
      }
      ++nidsWritten;
    }
  }
  testsOut << "};\n";
  log << "Written nids " << nidsWritten;

  return 0;
}

std::string toUpper(const std::string &str);
std::string getNid(const std::string &nidLine, std::string::size_type nidStartPos);
std::string stripNid(const std::string &nidLine);

std::string formTestSecion(const std::string &nidLine)
{
  const auto pos = nidLine.find("NID_");
  if(pos == std::string::npos)
    throw std::runtime_error("No NID_ in line");

  std::string ret = " NidUTInput {\n";
  const auto nid = getNid(nidLine, pos);
  //log << "NID to be added " << nid;
  ret += "  " + nid + ", nid::" + toUpper(stripNid(nid));
  ret += "\n },\n";

  return ret;
}

std::string formSoEntry(const std::string &nidLine)
{
  const auto pos = nidLine.find("NID_");
  if(pos == std::string::npos)
    throw std::runtime_error("No NID_ in line");

  const auto nid = getNid(nidLine, pos);
  const auto upperNid = toUpper(stripNid(nid));

  return "  static const auto " + upperNid + " = Nid(" + nid + ");\n";
}

std::string getNid(const std::string &nidLine, std::string::size_type nidStartPos)
{
  //log << "Processing " << nidLine << " nid start " << nidStartPos;
  auto i = nidStartPos;
  while(std::isalnum(nidLine[i]) || nidLine[i] == '_')
      ++i;

  //log << "Nid end " << i;
  return nidLine.substr(nidStartPos, i - nidStartPos);
}


std::string stripNid(const std::string &nid)
{
  const auto pos = nid.find('_');
  if(pos == std::string::npos)
    throw std::runtime_error("No undersore in nid");

  return nid.substr(pos + 1);
}

std::string toUpper(const std::string &str)
{
  std::string ret(str);
  std::transform(ret.begin(), ret.end(), ret.begin(), ::toupper);

  return ret;
}
