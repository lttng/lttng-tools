# if local wordsize is same as target, keep ctypes pointer function.
if ctypes.sizeof(ctypes.c_void_p) == __POINTER_SIZE__:
    POINTER_T = ctypes.POINTER
else:
    class IncorrectWordSizeError(TypeError):
        pass
    # required to access _ctypes
    import _ctypes
    # Emulate a pointer class using the approriate c_int32/c_int64 type
    # The new class should have :
    # ['__module__', 'from_param', '_type_', '__dict__', '__weakref__', '__doc__']
    # but the class should be submitted to a unique instance for each base type
    # to that if A == B, POINTER_T(A) == POINTER_T(B)
    ctypes._pointer_t_type_cache = {}
    def POINTER_T(pointee):
        # a pointer should have the same length as LONG
        fake_ptr_base_type = ctypes.__REPLACEMENT_TYPE__
        # specific case for c_void_p
        if pointee is None: # VOID pointer type. c_void_p.
            pointee = type(None) # ctypes.c_void_p # ctypes.c_ulong
            clsname = 'c_void'
        else:
            clsname = pointee.__name__
        if clsname in ctypes._pointer_t_type_cache:
            return ctypes._pointer_t_type_cache[clsname]
        # make template
        class _T(_ctypes._SimpleCData,):
            _type_ = '__REPLACEMENT_TYPE_CHAR__'
            _subtype_ = pointee
            def _sub_addr_(self):
                return self.value
            def __repr__(self):
                return '%s(%d)'%(clsname, self.value)
            def contents(self):
                raise IncorrectWordSizeError('This is not a ctypes pointer.')
            def __init__(self, **args):
                raise IncorrectWordSizeError('This is not a ctypes pointer. It is not instanciable.')
        _class = type('LP_%d_%s'%(__POINTER_SIZE__, clsname), (_T,),{})
        ctypes._pointer_t_type_cache[clsname] = _class
        return _class
