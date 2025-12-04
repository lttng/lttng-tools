#define MY_VAL 1
#define __MY_VAL 1

#define plop void

#define example(a,b) {a,b}

#define x(c,d) plopi(c,d)


extern plop x(int f, int g);

#define PRE "before"
#define POST " after"
#define APREPOST PRE POST
#define ANOTHER 1 2 3 4 5 6

char c1[] = "what";
char c2[] = "why" " though";
char c3[] = PRE POST;
char c4[] = APREPOST;

int i = MY_VAL;

#define DATE __DATE__
char c5[] = DATE;


#define API_NAME  "this is a test"
#define API_VER_MAJOR  3
#define API_VER_MINOR  1
#define API_VER_PATCH  0