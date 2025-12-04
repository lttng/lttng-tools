
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_HOST_MODULE := pybinding

LOCAL_COPY_FILES := \
	ctypeslib/clang2py.py:usr/lib/python/site-packages/ctypeslib/ \
	ctypeslib/codegen/clangparser.py:usr/lib/python/site-packages/ctypeslib/codegen/ \
	ctypeslib/codegen/codegenerator.py:usr/lib/python/site-packages/ctypeslib/codegen/ \
	ctypeslib/codegen/cursorhandler.py:usr/lib/python/site-packages/ctypeslib/codegen/ \
	ctypeslib/codegen/handler.py:usr/lib/python/site-packages/ctypeslib/codegen/ \
	ctypeslib/codegen/__init__.py:usr/lib/python/site-packages/ctypeslib/codegen/ \
	ctypeslib/codegen/typedesc.py:usr/lib/python/site-packages/ctypeslib/codegen/ \
	ctypeslib/codegen/typehandler.py:usr/lib/python/site-packages/ctypeslib/codegen/ \
	ctypeslib/codegen/util.py:usr/lib/python/site-packages/ctypeslib/codegen/ \
	ctypeslib/data/fundamental_type_name.tpl:usr/lib/python/site-packages/ctypeslib/data/ \
	ctypeslib/data/headers.tpl:usr/lib/python/site-packages/ctypeslib/data/ \
	ctypeslib/data/pointer_type.tpl:usr/lib/python/site-packages/ctypeslib/data/ \
	ctypeslib/data/string_cast.tpl:usr/lib/python/site-packages/ctypeslib/data/ \
	ctypeslib/data/structure_type.tpl:usr/lib/python/site-packages/ctypeslib/data/ \
	ctypeslib/dynamic_module.py:usr/lib/python/site-packages/ctypeslib/ \
	ctypeslib/experimental/byref_at.py:usr/lib/python/site-packages/ctypeslib/experimental/ \
	ctypeslib/__init__.py:usr/lib/python/site-packages/ctypeslib/

include $(BUILD_CUSTOM)

# $1: name of the python module to generate.
#     This will generate a file named '$1.py' in python library directory.
# $2: list of alchemy library modules separated by ':' (used to extract flags).
# $3: list of header file path with API to generate separated by ':'.
# $4: list of library (.so) path with API to generate separated by ':'.
define pybinding-macro

# - The call to TARGET_CC is to extract default incude directories
# - We extract other includes and flag from the alchemy generated file objects.flags
# - We force -fno-unsigned-char to make sure the binding uses ctype.c_char
#   for the type char even on arm where it is supposed to be unsigned
#   This assumes that the library does not depend on this...


PRIVATE_SO_FILES = $(shell echo "$4" | sed "s#:# #g")
$(call local-get-build-dir)/$1.py: PRIVATE_SO_FILES := $$(PRIVATE_SO_FILES)
$(call local-get-build-dir)/$1.py: PRIVATE_SRC_FILES = \
	$$(foreach header, $$(shell echo "$3" | sed "s#:# #g"), \
		$$(if $$(findstring undefined,$$(origin PRIVATE_CUSTOM_$$(header))), \
			$$(header), $$(shell echo $$(PRIVATE_CUSTOM_$$(header)) | sed "s#:# #g") \
		) \
	)
$(call local-get-build-dir)/$1.py: PRIVATE_OBJECT_FLAGS := $$(foreach lib, $$(shell echo "$2" | sed "s#:# #g"), $$(call module-get-build-dir,$$(lib))/$$(lib).objects.flags)
$(call local-get-build-dir)/$1.py: $(shell echo "$4" | sed "s#:# #g")
	@echo "$$(PRIVATE_MODULE): Generating $1 python binding"
	@echo "Private object flags: $$(PRIVATE_OBJECT_FLAGS)"
	@echo "Private so files: $$(PRIVATE_SO_FILES)"

	$(Q) PYTHONPATH=$(HOST_OUT_STAGING)/usr/lib/python/site-packages \
		$(HOST_OUT_STAGING)/usr/lib/python/site-packages/ctypeslib/clang2py.py \
		--kind acdefstu \
		$$(PRIVATE_SRC_FILES) \
		$$$$(echo $$(PRIVATE_SO_FILES) | tr ' ' '\n' | sed -E 's/^(.+)/-l \1/') \
		--target=$(if $(call streq,$(TARGET_ARCH),x64),x86_64,$(TARGET_ARCH)) \
		-o $$@ \
		\
		--clang-args=" \
			$$$$(echo | $(TARGET_CC) $(TARGET_GLOBAL_CFLAGS) -E -Wp,-v - 2>&1 | grep '^ /' | sed -E 's/^ (.+)/-I\1/' | tr '\n' ' ') \
			$$$$(sed -n -e 's/PRIVATE_C_INCLUDES :=//p' $$(PRIVATE_OBJECT_FLAGS) | tr ' ' '\n' | sed -E 's/^(.+)/-I\1/') \
			$$$$(sed -n -e 's/TARGET_GLOBAL_C_INCLUDES :=//p' $$(PRIVATE_OBJECT_FLAGS) | tr ' ' '\n' | sed -E 's/^(.+)/-I\1/') \
			$$$$(sed -n -e 's/PRIVATE_GLOBAL_CFLAGS :=//p' $$(PRIVATE_OBJECT_FLAGS)) \
			$$$$(sed -n -e 's/PRIVATE_CFLAGS :=//p' $$(PRIVATE_OBJECT_FLAGS)) \
			-fno-unsigned-char \
		"

LOCAL_CLEAN_FILES += $(call local-get-build-dir)/$1.py
LOCAL_COPY_FILES += $(call local-get-build-dir)/$1.py:usr/lib/python/site-packages/
LOCAL_DEPENDS_HOST_MODULES += host.pybinding
LOCAL_DEPENDS_MODULES := python
LOCAL_LIBRARIES += $(shell echo "$2" | sed "s#:# #g")

endef

# Register the macro in alchemy
$(call local-register-custom-macro,pybinding-macro)
