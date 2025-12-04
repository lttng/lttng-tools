

struct Name
{
  short member1;
  int member2;
  unsigned int member3;
  unsigned int member4;
  unsigned int member5;
} __attribute__((packed));

struct Name2
{
  short member1;
  int member2;
  unsigned int member3;
  unsigned int member4;
  unsigned int member5;
};

struct Node {
  unsigned int val1;
  void * ptr2;
  int * ptr3;
  struct Node2 * ptr4;
};

struct Node2 {
  unsigned char m1;
  struct Node * m2;
};

struct Node3 {
  struct Node * ptr1;
  unsigned char * ptr2;
  unsigned short * ptr3;
  unsigned int * ptr4;
  unsigned long * ptr5;
  unsigned long long * ptr6;
  double * ptr7;
  long double * ptr8;
  void * ptr9;
};

struct Node4 {
  struct Node f1;
  unsigned char f2;
  unsigned short f3;
  unsigned int f4;
  unsigned long f5;
  unsigned long long f6;
  double f7;
  long double f8;
};


enum myEnum {
ONE,
TWO,
FOUR = 4 
};

typedef struct
{
  long __val[2];
} my__quad_t;

typedef struct
{
  long a:3;
  long b:4;
  unsigned long long c:3;
  unsigned long long d:3;
  long f:2;
} my_bitfield;

typedef struct __attribute__((packed)) {
    int a;
    char c;
} mystruct;

struct Anon;
struct Anon2;

struct f {
    int x;
    float * fx[] ;
};
