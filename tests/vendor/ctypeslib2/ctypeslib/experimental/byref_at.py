from ctypes import *

"""
struct tagPyCArgObject {
	PyObject_HEAD
	ffi_type *pffi_type;
	char tag;
	union {
		char c;
		char b;
		short h;
		int i;
		long l;
#ifdef HAVE_LONG_LONG
		PY_LONG_LONG q;
#endif
		double d;
		float f;
		void *p;
	} value;
	PyObject *obj;
	int size; /* for the 'V' tag */
};
"""


class value(Union):
    _fields_ = [("c", c_char),
                ("h", c_short),
                ("i", c_int),
                ("l", c_long),
                ("q", c_longlong),
                ("d", c_double),
                ("f", c_float),
                ("p", c_void_p)]

# Thanks to Lenard Lindstrom for this tip: The sizeof(PyObject_HEAD)
# is the same as object.__basicsize__.


class PyCArgObject(Structure):
    _fields_ = [("PyObject_HEAD", c_byte * object.__basicsize__),
                ("pffi_type", c_void_p),
                ("tag", c_char),
                ("value", value),
                ("obj", c_void_p),
                ("size", c_int)]
    _anonymous_ = ["value"]

assert sizeof(PyCArgObject) == type(byref(c_int())).__basicsize__

print("sizeof(PyCArgObject)", sizeof(PyCArgObject))

for name, _ in PyCArgObject._fields_:
    print(name, getattr(PyCArgObject, name))

for name in "c h i l q d f p".split():
    print(name, getattr(PyCArgObject, name))
