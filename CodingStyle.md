# Coding style guide

It is said that there is no accounting for taste. However, when it comes to code, we are of the opinion that a _consistent_ style makes it easier to collaborate in a shared code base.

Style guidelines are bound to be controversial. Some conventions laid out in this guide have objective merit. However, most boil down to personal preferences of the original authors.

As such, this guide attempts to lay out the conventions used in the project so that new contributors can easily conform to them and minimize time lost during code review.

Contributions are expected to adhere to these guidelines.

## Migration from C

As the LTTng-tools project aims at supporting a broad range of compilers -- currently starting from GCC 4.8 and Clang 3.3 -- its build system is configured to use the C++11 standard.

LTTng-tools has historically been developped in C99 with liberal uses of GNU extensions. Since the release of LTTng 2.13, it has started a migration to C++.

In order to ease the transition, it underwent an initial migration phase which had a limited scope: build all existing C code as C++11.

As such, most of the project's code does not qualify as idiomatic C++ code. This migration is ongoing and expected to span across multiple release cycles.

However, new contributions are expected to conform the C++ style described in this guide. Some exceptions are allowed for small fixes which have to be back-ported to stable branches.

## Automated formatting

All the project's C++ files follow the [clang-format](https://clang.llvm.org/docs/ClangFormat.html) [style](https://clang.llvm.org/docs/ClangFormatStyleOptions.html) of the `.clang-format` file for whitespaces, indentation, and line breaks.

You _must_ format your changes with clang-format before you contribute a patch.

Note that clang-format 14 is required to use the project's `.clang-format` file.

Most text editors allow you to format a sub-section of a source file using clang-format to ensure it adheres to the project's style.

If you are submitting a change to existing source files, _do not run clang-format on the whole file_ as this may introduce more changes than you intended and _will_ cause your changes to be rejected.

## Tabs VS Spaces

While our founding mothers and fathers eschewed any consideration for non-English languages when designing the ASCII character encoding they, in a rare moment of technical decadence, decided to dedicate a character to the sole purpose of expressing tabulations.

This project makes use of this character to express indentations in its source files.

Note that while tab characters are used for semantic indentation purposes, spaces are perfectly fine to use for _visual_ alignment (e.g. ascii diagrams).

## Single line control flow statements

Single line control flow statements (if/for/while) are required to use braces.

```cpp
/* bad */
if  (my_thingy)
	do_the_thing();

/* good */
if  (my_thingy)  {
	do_the_thing();
}
```

## Naming

- Use snake case (e.g. `a_snake_case_name`) except for template parameters, which use camel case and end with `Type` (e.g. `ACamelCaseNameType`).

- Prefer using explicit and verbose names. For instance:
  - When naming a variable that indicates a count of bananas, prefer `banana_count` to `bananas`, `count`, or `n`.
  - When naming a function or method that validates and initializes a user profile, prefer `validate_and_initialize_user_profile()` to `set_up()`, `viup()`, `do_user_profile()`, `init()`.

- Avoid the use of overly generic terms like `data`, `ptr`, and `buffer`.

- Use an underscore prefix for private or protected methods and members, and member type names: `_try_connect()`, `class _user_count`, `int _version`.

- Name trivial setters and getters like the property name, without a verb (e.g. `set` and `get` prefixes).

  ```cpp
  /* good, gets the session's name. */
  session.name();
  /* good, sets the session's name. */
  session.name("my new name");

  /* good, non-trivial accessor */
  session.add_channel(my_channel);
  ```

- Use the `is` or `has` prefixes to name boolean properties or functions which return a `bool` type.

- Do not make-up abbreviations to shorten names. Term of art abbreviations are, however, acceptable. For example: `mpeg`, `ctf`, `cfg`, `init` are accepted. A notable exception to this rule applies to namespaces, see the "Use of namespaces/Aliases" section.

## Comments

In general, comments should focus on _why_ something is done and document the assumptions the code was built upon. They should not repeat what it does in plain english except if the code is particularily complex. Keep in mind that what may be obvious to you right now may not be obvious to reviewers... or your future self.

Also, write comments in grammatically-sound English and avoid writing using telegraph style:

```cpp
/* Bad: init cfg */

/* Bad: init cfg before reply */

/* Good: The configuration must be initialized before replying since it initializes the user's credentials. */
```

## Include guards

Header files must use include guards to prevent multiple inclusion issues. To avoid collisions, the name of include guards must be as specific as possible and include the name of the file.

```cpp
/* In file thingy-handler.hpp */

#ifndef LTTNG_CONSUMERD_THINGY_HANDLER
#define LTTNG_CONSUMERD_THINGY_HANDLER

/* Some briliant code. */

#endif  /* LTTNG_CONSUMERD_THINGY_HANDLER */
```


## Use of namespaces

Make liberal use of namespaces. Very little should be available in the `lttng`,
let alone global, namespace.

Moreover, prefer to use anonymous namespaces to the `static`  keyword to restrict the visibility of a symbol to its translation unit.

### Do not pollute the global namespace

Never use the `using` directive to import the contents of a namespace. If a namespace is used often in a file, define an alias.

### Aliases

Within a translation unit, it is acceptable to abbreviate commonly-used namespace names to define an alias. For instance, the file containing the implementation of the `food::fruits::citrus::grapefruit` can use the `ffc` namespace alias for brievety.

```cpp
/* In file grapefruit.cpp */

namespace ffc = food::fruits::citrus;

ffc::grapefruit::grapefruit()
{
    // ...
}
```

## File layout example

```cpp
/*
 * Copyright (C) 20xx Robert Binette <bob@codebleu.qc.ca>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_THING_DOER_H
#define LTTNG_THING_DOER_H

/* Mind the order of inclusions, in alphabetical order per category. */

/* Project-local headers. */
#include "my-local-stuff.hpp"
#include "utils.hpp"

/* Project-wide headers. */
#include <vendor/optional.hpp>

/* System headers. */
#include <functional>
#include <string>
#include 

namespace lttng {
namespace sessiond {

class things;

using on_new_name_function = std::function<void(const std::string& name)>;

class thing_doer : public lttng::sessiond::doer {
public:
	explicit thing_doer(const std::string& name);

	virtual void do() override final;
	const std::string& name() const;

private:
	unsigned int _count_things(std::vector) const noexcept;

	const std::string _name;
};

} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_THING_DOER_H */
```

## Miscelaneous guidelines

In general, the project’s contributors make an effort to follow, for C++11 code:

[The C++ Core Guidelines](https://github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md)

[Scott Meyers’s “Effective Modern C++”](https://www.oreilly.com/library/view/effective-modern-c/9781491908419/)

Here are a couple of reminders:
* When defining a class, put constructors as the first methods, whatever their access (public/protected/private), then the destructor, and then the rest.

* Declare variables as close to where they are used as possible.

* Use auto when possible.

* Use const as much as possible, even for pointer (const char* const) and numeric values (const unsigned int) which never need to change.

* Make methods const noexcept or const as much as possible.

* Make constructors explicit unless you really need an implicit constructor (which is rare).

* Use `std::unique_ptr` to manage memory when possible.
  * However, use references (`*my_unique_ptr`) and raw pointers (`my_unique_ptr.get()`) when not transferring ownership.
  * Only use `std::shared_ptr` when ownership is conceptually shared.

* Use `nullptr`, not `NULL` nor `0`.

* Return by value (rvalue) instead of by output parameter (non-const lvalue reference), even complex objects, unless you can prove that the performance is improved when returning by parameter.

* For a function parameter or a return value of which the type needs to be a reference or pointer, use:
  * **If the value is mandatory**, a reference.
  * **If the value is optional**, a raw pointer.

* Don't use `std::move()` when you already have an rvalue, which means:
  * Don't write `return std::move(...);` as this can interfere with RVO (Return Value Optimization).
  * Don't use `std::move()` with a function call (`std::move(func())`).

* For each possible move/copy constructor or assignment operator, do one of:
  * Write a custom one.
  * Mark it as defaulted (`default`)
  * Mark it as deleted (`delete`).

* Use scoped enumerations (`enum class`).

* Mark classes known to be final with the `final` keyword.

* Use type aliases (`using`), not type definitions (`typedef`).

* Use anonymous namespaces for local functions instead of `static`.

* Return a structure with named members instead of a generic container such as `std::pair` or `std::tuple`.

* When a class inherits a base class with virtual methods, use the `override` keyword to mark overridden virtual methods, and do not use the `virtual` keyword again (as the method is already known to be virtual).

* Define overloaded operators only if their meaning is obvious, unsurprising, and consistent with the corresponding built-in operators.

  For example, use `|` as a bitwise or logical-or, not as a shell-style pipe.

* Use RAII wrappers when managing system resources or interacting with C libraries.

  In other words, don't rely on ``goto``s and error labels to clean up as you would do in C.

* Throw an exception when there's an unexpected, exceptional condition,
  [including from a constructor](https://isocpp.org/wiki/faq/exceptions#ctors-can-throw), instead of returning a status code.

  However, be mindful of the exception-safety of your users. For instance, `liblttng-ctl` exposes a C interface meaning that is must catch and handle all exceptions, most likely by returning a suitable error code.

* Accept a by-value parameter and move it (when it's moveable) when you intend to copy it anyway. You can do this with most STL containers.

## C Style (historical)

The coding style used for this project follows the the Linux kernel guide lines, except that brackets `{`, `}` should typically be used even for single-line if/else statements. Please refer to:

- doc/kernel-CodingStyle.txt (copied from the Linux 3.4.4 tree).

- Linux kernel scripts/checkpatch.pl for a script which verify the patch
  coding style.

For header files, please declare the following in this order:

1) `#define`

 - Default values should go in: src/common/defaults.h
 - Macros used across the project: src/common/macros.h

2) Variables

 - No _static_ in a header file! This is madness.
 - Use _extern_ if the global variable is set else where.

3) Function prototype

Furthermore, respect the name spacing of files for each non-static symbol visiable outside the scope of the C file. For instance, for the utils.c file in libcommon, every call should be prefixed by "utils_*".

### Error handling

In legacy C-style code, we ask to use one single return point in a function. For that, we uses the "goto" statement for the error handling creating one single point for error handling and return code. See the following example:

```c
int some_function(...)
{
	int ret;
	[...]

	if (ret != 0) {
		goto error;
	}

	[...]
error:
	return ret;
}
```
