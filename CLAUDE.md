# LTTng-tools project context

## Project overview

LTTng-tools is a set of components for controlling LTTng tracing.

Main components:

- **`lttng-sessiond`**: Core tracing control daemon.

   Manages recording sessions (including domains, channels, and event rules) and triggers.

   Receives commands from clients (through liblttng-ctl) and replies to them (Unix socket).

   Spawns and manages `lttng-consumerd` instances.

   Communicates with the user space and Linux kernel tracers.

   Communicates with one or more `lttng-relayd` instances if needed.

- **`lttng-consumerd`**: Trace data consumption daemon.

  Consumes trace data from ring buffers shared with tracers.

  Writes traces to local files or sends it over the network to an `lttng-relayd` instance.

  Separate instances for Linux kernel tracing and user space tracing.

  Spawned by `lttng-sessiond`.

- **`lttng-relayd`**: Network-based trace relay daemon.

  Receives trace data from `lttng-consumerd` instances and commands from `lttng-sessiond` (TCP).

  Writes remote traces (locally).

  Supports LTTng live trace reading (TCP) for tools like Babeltrace: viewers can watch traces as they're being written.

- **`lttng`**: CLI to control tracing.

  Wraps almost all of the liblttng-ctl C API to control the session daemon on the command line.

- **liblttng-ctl**: C API to communicate with the session daemon (Unix socket).

## Directory structure

- `src/`: Whole source.
  - `bin/`: Main executables.
    - `lttng/`: `lttng` client CLI tool.
      - `commands/`: Sub-commands.
    - `lttng-sessiond/`: Session daemon.
    - `lttng-relayd/`: Relay daemon.
    - `lttng-consumerd/`: Consumer daemon.
  - `lib/lttng-ctl/`: liblttng-ctl.
  - `common/`: Common code and utilities.
    - `error.hpp`: Error management API. Use the `*_FMT()` macros in new code.
    - `format.hpp`: Offers `lttng::format()` which works like `std::format()`, but for C++11. Always use `lttng::format()` to format strings in new code.
    - `make-unique.hpp`: Offers `lttng::make_unique()` which works like `std::make_unique`, but for C++11. Always use `lttng::make_unique()` to create unique pointers in new code.
    - `scope-exit.hpp`: Offers `lttng::scope_exit` which works like `std::experimental::scope_exit`.
  - `vendor`: Third-party vendored code. Do _not_ edit those or add anything here.
    - `argpar/`: Custom CLI argument parser. Use for new CLI parsing code.
    - `optional.hpp`: Offers `nonstd::optional`, which works like `std::optional`, but for C++11. Always use `nonstd::optional` for optional values in new code.
- `include/lttng/`: Public liblttng-ctl headers.
- `tests/`: Test suites.
  - `regression/`: Regression tests.
  - `stress/`: Stress tests.
  - `unit/`: Unit tests.
  - `utils/`: Testing utilities.
- `doc/`: Documentation.
  - `man/`: Manual pages (original Asciidoc format, _not_ Asciidoctor).
  - `doc/api/liblttng-ctl/`: liblttng-ctl C API documentation (Doxygen project; much of the documentation is part of the headers themselves).

## Build system

- Using GNU Autotools (Automake, Autoconf, Libtool).

- Configuration process:

  ```bash
  ./bootstrap
  ./configure CFLAGS='-O0 -g3' CXXFLAGS='-O0 -g3'
  ```

  Useful `configure` script options:

  - `--enable-python-bindings`: Build Python bindings.
  - `--disable-man-pages`: Skip manual page generation.
  - `--enable-api-doc`: Build the liblttng-ctl C API documentation.

  If you modify `configure.ac`: configure again.

- Build process:

  ```bash
  make -j$(nproc)
  ```

- Testing process:

  ```bash
  make check
  ```

## Programming language

The project is actively migrating from C99 to C++11:

- The extensions of most C99 files were renamed to `.cpp` and `.hpp` without altering the C code (build as C++).
- When editing existing files, use C++11 liberally.
- All new code must be in C++11.

Do _not_ use C++14 or later: always use C++11.

Consider the following alternatives:

- Instead of `std::format()`, use `lttng::format()` from `<common/format.hpp>`.
- Instead of `std::optional`, use `nonstd::optional` from `<vendor/optional.hpp>`.
- Instead of `std::make_unique()`, use `lttng::make_unique()` from `<common/make-unique.hpp>`.
- Instead of `std::experimental::scope_exit`, use `lttng::scope_exit` from `<common/scope-exit.hpp>`.

## Coding style

Do not bother following an exact coding style for whitespaces: run `./format-cpp` which runs clang-format on all the C++ files.

## Coding convention

### Naming

- **Variables**, **functions**, **methods**, and **namespaces**: Use `snake_case`.

  Examples: `variable_name`, `function_name()`.

- **Definitions** and **enumerators**: Use `UPPERCASE_SNAKE_CASE`.

  Example: `#define USEC_PER_SEC 1000000ULL`.

- **Template parameter**: Use `CamelCase` + `Type` suffix.

  Example: `template <typename ElementType>`.

- **Private/protected members**: Prefix with `_`.

  Example: `_private_method()`.

Rules:

- Prefer verbose names: `banana_count` over `n`.
- Avoid generic terms like `data`, `ptr`, `buffer`; be specific.
- Do not use abbreviations to shorten names, except for very common ones.
- Name trivial setters and getters like the property name, without a verb (not `set` and `get` prefixes).
- Use the `is` or `has` prefixes to name boolean properties or functions which return a `bool` type.

### Comments

In general, comments should focus on _why_ something is done and document the assumptions the code was built upon. They should not repeat what it does in plain English except if the code is very complex.

Write comments in grammatically-sound English; don't write in telegraph style.

### Include guards

Header files must use include guards to prevent multiple inclusion issues. To avoid collisions, the name of include guards must be as specific as possible and include the name of the file.

Example:

```cpp
/* In file thingy-handler.hpp */

#ifndef LTTNG_CONSUMERD_THINGY_HANDLER
#define LTTNG_CONSUMERD_THINGY_HANDLER

/* Some briliant code. */

#endif  /* LTTNG_CONSUMERD_THINGY_HANDLER */
```

### Namespaces

Make liberal use of namespaces. Very little should be available in the `lttng`, let alone global, namespace.

Moreover:

- In a `.cpp` file, always use the anonymous namespace instead of the `static` keyword.
- In a `.hpp` file, always use the `details` namespace to hide implementation details.

Never use the `using` directive to import the contents of a namespace.

If a namespace is used often in a file, define a namespace alias.

### Error management

- Use RAII wrappers when managing system resources or interacting with C libraries.

  Don't use `goto` and error labels.

- Throw an exception when there's an unexpected, exceptional condition, including from a constructor, instead of returning a status code.

  However, don't make public liblttng-ctl C functions throw anything.

### Notable rules

- When defining a class, put constructors as the first methods, whatever their access (`public`/`protected`/`private`), then the destructor, and then the rest.
- Declare variables as close to where they are used as possible.
- Use `auto` when possible.
- Use `const` as much as possible, even for pointer (`const char* const`) and numeric values (`const unsigned int`) which never need to change.
- Make methods `const noexcept` or `const` as much as possible.
- Make constructors `explicit` unless you really need an implicit constructor (which is rare).

- Use `std::unique_ptr` to manage memory when possible.
  - However, use references (`*my_unique_ptr`) and raw pointers (`my_unique_ptr.get()`) when not transferring ownership.

- Use `nullptr`, not `NULL` nor `0`.
- Return by value (rvalue) instead of by output parameter (non-const lvalue reference), even complex objects, unless you can prove that the performance is improved when returning by parameter.

- For a function parameter or a return value of which the type needs to be a reference or pointer, use:
  - **If the value is mandatory**: a reference.
  - **If the value is optional**: a raw pointer.

- Don't use `std::move()` when you already have an rvalue, which means:
  - Don't write `return std::move(...);` as this can interfere with RVO.
  - Don't use `std::move()` with a function call (`std::move(func())`).

- For each possible move/copy constructor or assignment operator, do one of:
  - Write a custom one.
  - Mark it as defaulted (`default`)
  - Mark it as deleted (`delete`).

- Use scoped enumerations (`enum class`).
- Mark classes known to be final with the `final` keyword.
- Use type aliases (`using`), not type definitions (`typedef`).
- Return a structure with named members instead of a generic container such as `std::pair` or `std::tuple`.
- When a class inherits a base class with virtual methods, use the `override` keyword to mark overridden virtual methods, and do not use the `virtual` keyword again (as the method is already known to be virtual).

- Define overloaded operators only if their meaning is obvious, unsurprising, and consistent with the corresponding built-in operators.

  For example, use `|` as a bitwise or logical-or, not as a shell-style pipe.

- Accept a by-value parameter and move it (when it's moveable) when you intend to copy it anyway.

  You can do this with most STL containers.

## Git commit

Run `./format-cpp` before you stage files.

Always commit with the `-s` option (adds `Signed-off-by` line).

Limit commit messages to 72 columns, except for literal blocks.

Use a style similar to Markdown, except for headings:

```
My heading
==========
Some text here.
```

Notable subsystem names:

- `relayd`: Relay daemon.
- `sessiond`: Session daemon.
- `lttng`: CLI tool.
- `ust-consumerd`: User space consumer daemon.
- `kernel-consumerd`: Linux kernel space consumer daemon.
- `consumerd`: Common consumer daemon.
- `common`: Anything in `src/common/`.
- `lttng-ctl`: liblttng-ctl.
- `mi`: Machine interface of LTTng CLI tool.

### Standard commit message

```
<subsystem>: <short subject>

<Detailed explanation of the "why" behind the change>

<Implementation details>
```

Use titled sections if the message is very long.

### Bug fix commit message

Example:

```
Fix: relayd: missing thingy in the doodad folder on error

Observed issue
==============
After a communication error, the relay daemon will not produce
a thingy in the doodad folder. This results in the knickknack
baring the foo.

Steps to reproduce (list of commands or narrative description).

Cause
=====
The thingy_do_the_doodad() callback is only invoked when
the thread responsible for receiving messages and dispatching
them to the correct actors encounters an emoji.

However, an emoji is not guaranteed to be present in the ELF
section header [1].

Solution
========
Flushing the doodad on every reception of a thingo ensures that
the thingy is present in the doodad folder even if a communication
error occurs.

Known drawbacks
===============
Flushing the doodad too often may spam the widget and result in
degradation of the gizmo. This doesn't matter right now since
it happens exactly once per blue moon.

If this becomes a serious issue, we could machine learn the MVP
through the big O terminal.

References
==========
[1] https://www.thedocs.com/elf/proving-my-point-unambiguously.aspx
```
