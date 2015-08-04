#include <dlfcn.h>

int main()
{
	void *handle;
	int (*foo)();

	handle = dlopen("libfoo.so", RTLD_LAZY);
	foo = dlsym(handle, "foo");

	(*foo)();

	dlclose(handle);

	return 0;
}
