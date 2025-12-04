int twice(int i)
{
    return 2 * i;
}

int (*ptwice)(int) = &twice;

int (*get_func_ptr(void))(int)
{
    return &twice;
}

typedef int (*func_type)(int);

int call_func(func_type func, int func_arg)
{
  return func(func_arg);
}

struct cbs {
    int (*foo)(int);
    char c;
    int (*bar)(int);
};


int call_cbs(const struct cbs* cbs, int foo_arg, int bar_arg)
{
  return cbs->foo(foo_arg) + cbs->bar(bar_arg);
}
