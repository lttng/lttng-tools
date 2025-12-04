// sample from Stackoverflow
// #include "test-cpp-inherit.h"

namespace MySpace {

struct Simple {
    int i;
};

class Classy {
    public:
    float f;
    void myMethod() {  // Method/function defined inside the class
      cout << "Hello World!";
    }
    private:
    long line;
};

}

class Base {

private:
  int MyPrivateInt;
protected:
  int MyProtectedInt;
public:
  int MyPublicInt;
};

class Extended : Base
{
public:
    Extended();
    int MyInt;
    virtual void method() const;
};