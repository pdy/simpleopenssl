#ifndef SO_SIMPLELOG_H_
#define SO_SIMPLELOG_H_

#include <type_traits>
#include <sstream>
#include <iostream>

class SimpleLog
{
public:
  ~SimpleLog()
  {
    std::cout << m_ss.str() << std::endl;
  }

  template
  <
    typename T,
    typename = typename std::enable_if<std::is_integral<T>::value>::type
  > 
  SimpleLog& operator<<(T val)
  {
    m_ss << val;
    return *this;
  }

  SimpleLog& operator<<(const std::string &str)
  {
    m_ss << str;
    return *this;
  }

  SimpleLog& operator<<(const std::stringstream &ss)
  {
    m_ss << ss.str();
    return *this;
  }

  SimpleLog& operator<<(const char *c_str)
  {
    m_ss << c_str;
    return *this;
  }

  std::ostream& stream() const
  {
    return std::cout;
  }

private:
  std::stringstream m_ss;
};

#define log (SimpleLog{})

#endif
