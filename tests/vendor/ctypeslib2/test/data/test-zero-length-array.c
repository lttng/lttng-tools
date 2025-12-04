struct example_detail {
	int first;
	int last;
};

struct example {
	int argsz;
	int flags;
	int count;
	struct example_detail details[];
};

typedef char array[];
struct blah {
    int N;
    char varsize[];
};
struct bar {
    int N;
    char * varsize[];
};