typedef struct _complex1 {
	struct {
		int a;
	};
} complex1, *pcomplex1;

typedef struct _complex2 {
	struct {
		int a;
	};
	struct {
        long b;
	};
} complex2, *pcomplex2;

typedef struct _complex3 {
    union {
	    struct {
		    int a;
	    };
	    struct {
            long b;
            union {
                int c;
                struct {
                    long long d;
                    char e;
                };
            };
	    };
	    struct {
            long f;
	    };
	    int g;
    };
} complex3, *pcomplex3;

typedef struct _complex4 {
	struct {
		short a;
	};
	struct  {
		short b;
		char c;
	};
} complex4, *pcomplex4;

typedef struct _complex5 {
	struct {
	    int x;
		char a;
	};
	struct __attribute__((packed)) {
		char b;
	    int c;
	};
} complex5, *pcomplex5;

typedef struct _complex6 {
	struct {
		char a;
	};
	struct __attribute__((packed)) {
		char b;
	};
} complex6, *pcomplex6;

