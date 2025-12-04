/* padding */

struct Name
{
  short member1;
  int member2;
  long long member3;
} __attribute__((packed));

struct Name2
{
  short member1;
  int member2;
  long long member3;
};

struct Name3
{
  short member1;
  long member2;
  short member3;
  long member4;
  short member5;
  long member6;
} __attribute__((packed));

struct Name4
{
  short member1;
  long member2;
  short member3;
  long member4;
  short member5;
  long member6;
};

struct Node {
  unsigned int val1;
  void * ptr2;
  int * ptr3;
  unsigned char val4;
};

struct Node2 {
  unsigned char m1;
  struct Node * m2;
};

struct Node3 {
  unsigned char m1;
  struct Node m2;
  unsigned char m3;
};

struct Node4 {
  unsigned char m1;
  unsigned short m2;
  struct Node * m3;
};

struct Node5 {
  unsigned int m1;
  unsigned short m2;
};


/** padding in bitfields */
typedef struct
{
  long a:3;
  long b:4;
  unsigned long long c:3;
  unsigned long long d:3;
  long f:2;
} my_bitfield;


