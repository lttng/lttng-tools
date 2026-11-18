/*
 * Copyright (C) 2025-2026 Philippe Proulx <eeppeliteloop@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
 * IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */

/*
 *                                 _      __
 *                          __ _  (_)__  / /_
 *                         /  ' \/ / _ \/ __/
 *                        /_/_/_/_/_//_/\__/
 *                                 v0.11.0
 *
 * This header offers mint::mint(), which converts terminal attribute
 * tags similar to BBCode into actual terminal SGR codes, as well as
 * related utilities to escape text and to detect terminal support.
 *
 * You may copy this header as is to your project. The only requirements
 * are Linux and C++11.
 */

#ifndef MINT_HPP
#define MINT_HPP

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace mint {
namespace internal {

inline bool endsWith(const std::string& str, const char * const suffix) noexcept
{
    const auto suffixLen = std::strlen(suffix);

    if (str.size() < suffixLen) {
        return false;
    }

    return str.find(suffix, str.size() - suffixLen) != std::string::npos;
}

/*
 * Returns the value of the environment variable `name`, or an empty
 * string if it's not set.
 */
inline std::string getEnv(const char * const name)
{
    const auto value = std::getenv(name);

    return value ? value : "";
}

struct TrueColor final
{
    std::uint8_t r;
    std::uint8_t g;
    std::uint8_t b;
};

struct StackFrame final
{
    void setFgColor(const std::uint8_t colorCodeOffset) noexcept
    {
        hasFgColor = true;
        fgColorCodeOffset = colorCodeOffset;
    }

    void setBgColor(const std::uint8_t colorCodeOffset) noexcept
    {
        hasBgColor = true;
        bgColorCodeOffset = colorCodeOffset;
    }

    void setFgTrueColor(const TrueColor& color) noexcept
    {
        hasFgTrueColor = true;
        fgTrueColor = color;
    }

    void setBgTrueColor(const TrueColor& color) noexcept
    {
        hasBgTrueColor = true;
        bgTrueColor = color;
    }

    bool hasBold = false;
    bool hasDim = false;
    bool hasUnderline = false;
    bool hasItalic = false;
    bool hasReverse = false;
    bool hasBright = false;
    bool hasFgColor = false;
    std::uint8_t fgColorCodeOffset;
    bool hasBgColor = false;
    std::uint8_t bgColorCodeOffset;
    bool hasFgTrueColor = false;
    TrueColor fgTrueColor;
    bool hasBgTrueColor = false;
    TrueColor bgTrueColor;
};

using Stack = std::array<StackFrame, 5>;

/*
 * Helper for mint().
 *
 * Performs the conversion if `emitSgrCodes` is true at construction
 * time and makes the resulting string available as takeStr().
 */
class Parser final
{
public:
    explicit Parser(const char * const begin, const char * const end, const bool emitSgrCodes,
                    const bool hasTrueColorSupport) :
        _begin {begin},
        _at {begin},
        _end {end},
        _emitSgrCodes {emitSgrCodes},
        _hasTrueColorSupport {hasTrueColorSupport}
    {
        _result.reserve((end - begin) * 3);
        this->_parse();
    }

    std::string takeStr()
    {
        return std::move(_result);
    }

private:
    /*
     * Appends the decimal representation of `value` to `_result`.
     */
    void _appendInt(const std::uint8_t value)
    {
        if (value >= 100) {
            _result += '0' + (value / 100);

            const auto rem = value % 100;

            _result += '0' + (rem / 10);
            _result += '0' + (rem % 10);
        } else if (value >= 10) {
            _result += '0' + (value / 10);
            _result += '0' + (value % 10);
        } else {
            _result += '0' + value;
        }
    }

    /*
     * Throws `std::runtime_error` with a formatted message including
     * the current offset and `msg`.
     */
    [[noreturn]] void _throw(const std::string& msg) const
    {
        std::ostringstream ss;

        ss << "At offset " << (_at - _begin) << ": " << msg;
        throw std::runtime_error {ss.str()};
    }

    /*
     * Throws `std::runtime_error` with a formatted message including
     * the offset of `pos` and `msg`.
     */
    [[noreturn]] void _throw(const char * const pos, const std::string& msg) const
    {
        std::ostringstream ss;

        ss << "At offset " << (pos - _begin) << ": " << msg;
        throw std::runtime_error {ss.str()};
    }

    /*
     * Appends the SGR codes (if required) from the attributes
     * of `frame`.
     */
    void _appendSgrCode(const StackFrame& frame)
    {
        if (!_emitSgrCodes) {
            return;
        }

        /* Reset first */
        _result += "\033[0";

        if (frame.hasBold) {
            _result += ";1";
        }

        if (frame.hasDim) {
            _result += ";2";
        }

        if (frame.hasItalic) {
            _result += ";3";
        }

        if (frame.hasUnderline) {
            _result += ";4";
        }

        if (frame.hasReverse) {
            _result += ";7";
        }

        if (_hasTrueColorSupport && frame.hasFgTrueColor) {
            /* True color foreground */
            _result += ";38;2;";
            this->_appendInt(frame.fgTrueColor.r);
            _result += ';';
            this->_appendInt(frame.fgTrueColor.g);
            _result += ';';
            this->_appendInt(frame.fgTrueColor.b);
        } else if (frame.hasFgColor) {
            /* Basic foreground color */
            _result += ';';
            this->_appendInt((frame.hasBright ? 90 : 30) + frame.fgColorCodeOffset);
        }

        if (_hasTrueColorSupport && frame.hasBgTrueColor) {
            /* True color background */
            _result += ";48;2;";
            this->_appendInt(frame.bgTrueColor.r);
            _result += ';';
            this->_appendInt(frame.bgTrueColor.g);
            _result += ';';
            this->_appendInt(frame.bgTrueColor.b);
        } else if (frame.hasBgColor) {
            /* Basic background color */
            _result += ';';
            this->_appendInt(40 + frame.bgColorCodeOffset);
        }

        /* End of SGR code */
        _result += 'm';
    }

    /*
     * Converts the hex digit character `*pos` to its numeric value.
     *
     * Throws `std::runtime_error` if not a valid hex digit.
     */
    std::uint8_t _hexDigitValue(const char * const pos) const
    {
        const auto c = *pos;

        if (c >= '0' && c <= '9') {
            return c - '0';
        } else if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }

        std::ostringstream ss;

        ss << "invalid hex digit `" << c << "` in true color specifier";
        this->_throw(pos, ss.str());
    }

    /*
     * Tries to parse 6 hex digits as a true color.
     *
     * Throws `std::runtime_error` on error.
     */
    TrueColor _tryParseHexColor()
    {
        /* Need at least 6 characters */
        if (_end - _at < 6) {
            this->_throw(_at - 1, "incomplete true color specifier");
        }

        const TrueColor color {
            static_cast<std::uint8_t>(
                (this->_hexDigitValue(_at + 0) << 4) | this->_hexDigitValue(_at + 1)
            ),
            static_cast<std::uint8_t>(
                (this->_hexDigitValue(_at + 2) << 4) | this->_hexDigitValue(_at + 3)
            ),
            static_cast<std::uint8_t>(
                (this->_hexDigitValue(_at + 4) << 4) | this->_hexDigitValue(_at + 5)
            ),
        };

        _at += 6;
        return color;
    }

    /*
     * Tries to parse a color letter, returning the corresponding ANSI
     * color _offset_.
     *
     * Throws `std::runtime_error` on error.
     */
    std::uint8_t _tryParseBasicColor()
    {
        if (_at == _end) {
            this->_throw("incomplete color specifier");
        }

        const auto letterAt = _at;
        const auto c = *_at;

        ++_at;

        switch (c) {
        case 'k':
            return 0;
        case 'r':
            return 1;
        case 'g':
            return 2;
        case 'y':
            return 3;
        case 'b':
            return 4;
        case 'm':
            return 5;
        case 'c':
            return 6;
        case 'w':
            return 7;
        case 'd':
            return 9;
        default:
            {
                std::ostringstream ss;

                ss << "unknown color specifier letter `" << c << "`";
                this->_throw(letterAt, ss.str());
            }
        }
    }

    /*
     * Pushes `frame`, which the opening tag at `tagAt` describes, onto
     * the current stack.
     *
     * Throws `std::runtime_error` on error.
     */
    void _stackPush(const StackFrame& frame, const char * const tagAt)
    {
        if (_stackLen >= _stack.size()) {
            std::ostringstream ss;

            ss << "maximum nesting depth (" << (_stack.size() - 1) << ") exceeded";
            this->_throw(tagAt, ss.str());
        }

        _stack[_stackLen] = frame;
        ++_stackLen;
    }

    /*
     * Pops a frame from the current stack.
     *
     * The current stack must not be empty.
     */
    void _stackPop()
    {
        assert(_stackLen > 0);
        --_stackLen;
    }

    StackFrame& _stackBack() noexcept
    {
        return _stack[_stackLen - 1];
    }

    /*
     * Parses a complete opening tag, from `[` to `]` (included),
     * returning a corresponding frame.
     */
    StackFrame _parseOpenTag()
    {
        StackFrame frame;

        /* Skip `[` */
        const auto startAt = _at;

        assert(*_at == '[');
        ++_at;

        /* Parse tag content flexibly */
        while (_at != _end && *_at != ']') {
            if (*_at == ' ') {
                /* Skip space */
                ++_at;
            } else if (*_at == '!') {
                /* Bold */
                frame.hasBold = true;
                ++_at;
            } else if (*_at == '-') {
                /* Dim */
                frame.hasDim = true;
                ++_at;
            } else if (*_at == '_') {
                /* Underline */
                frame.hasUnderline = true;
                ++_at;
            } else if (*_at == '\'') {
                /* Italic */
                frame.hasItalic = true;
                ++_at;
            } else if (*_at == '^') {
                /* Reverse video */
                frame.hasReverse = true;
                ++_at;
            } else if (*_at == '*') {
                /* Bright foreground modifier */
                frame.hasBright = true;
                ++_at;
            } else if (*_at == ':') {
                /* Background color */
                ++_at;

                if (_at != _end && *_at == '#') {
                    /* True color background */
                    ++_at;
                    frame.setBgTrueColor(this->_tryParseHexColor());
                } else {
                    /* Basic background color */
                    frame.setBgColor(this->_tryParseBasicColor());
                }
            } else if (*_at == '#') {
                /* True color foreground */
                ++_at;
                frame.setFgTrueColor(this->_tryParseHexColor());
            } else {
                /* Basic foreground color */
                frame.setFgColor(this->_tryParseBasicColor());
            }
        }

        /* Expect `]` */
        if (_at == _end || *_at != ']') {
            this->_throw("expecting `]` to terminate the opening tag");
        }

        /* Check for empty tag */
        if (!frame.hasBold && !frame.hasDim && !frame.hasUnderline && !frame.hasItalic &&
                !frame.hasReverse && !frame.hasBright && !frame.hasFgColor && !frame.hasBgColor &&
                !frame.hasFgTrueColor && !frame.hasBgTrueColor) {
            this->_throw(startAt, "empty opening tag");
        }

        ++_at;
        return frame;
    }

    void _parse()
    {
        /* Initialize with default frame (no attributes) */
        this->_stackPush(StackFrame {}, _begin);

        /* Read each character */
        while (_at != _end) {
            if (*_at == '\\') {
                /* Escape sequence */
                const auto startAt = _at;

                ++_at;

                if (_at == _end) {
                    this->_throw(startAt, "incomplete escape sequence at end of string");
                }

                if (*_at == '\\' || *_at == '[') {
                    _result += *_at;
                    ++_at;
                } else {
                    std::ostringstream ss;

                    ss << "invalid escape sequence `\\" << *_at << "`";
                    this->_throw(startAt, ss.str());
                }
            } else if (*_at == '[') {
                const auto startAt = _at;

                /* Check if it's a closing tag: `[/...]` */
                if (_at + 1 < _end && *(_at + 1) == '/') {
                    /* Count the number of consecutive slashes */
                    auto slashAt = _at + 1;
                    Stack::size_type slashCount = 0;

                    while (slashAt < _end && *slashAt == '/') {
                        ++slashCount;
                        ++slashAt;
                    }

                    /* Expect `]` after the slashes */
                    if (slashAt == _end || *slashAt != ']') {
                        this->_throw(startAt, "unterminated closing tag");
                    }

                    /* Validate we have enough frames to pop */
                    if (_stackLen <= slashCount) {
                        std::ostringstream ss;

                        ss << "unbalanced closing tag: attempting to close " << slashCount <<
                              " level(s), but only " << (_stackLen - 1) << " level(s) are open";
                        this->_throw(startAt, ss.str());
                    }

                    /* Pop `slashCount` frames */
                    for (Stack::size_type i = 0; i < slashCount; ++i) {
                        this->_stackPop();
                    }

                    this->_appendSgrCode(this->_stackBack());
                    _at = slashAt + 1;
                } else {
                    /* Expect opening tag */
                    auto frame = _parseOpenTag();

                    /* Inherit attributes from current frame */
                    if (!frame.hasBold && this->_stackBack().hasBold) {
                        frame.hasBold = true;
                    }

                    if (!frame.hasDim && this->_stackBack().hasDim) {
                        frame.hasDim = true;
                    }

                    if (!frame.hasUnderline && this->_stackBack().hasUnderline) {
                        frame.hasUnderline = true;
                    }

                    if (!frame.hasItalic && this->_stackBack().hasItalic) {
                        frame.hasItalic = true;
                    }

                    if (!frame.hasReverse && this->_stackBack().hasReverse) {
                        frame.hasReverse = true;
                    }

                    if (!frame.hasBright && this->_stackBack().hasBright) {
                        frame.hasBright = true;
                    }

                    /*
                     * Only inherit a true color if the tag itself sets
                     * no color of the same kind.
                     */
                    if (!frame.hasFgTrueColor && !frame.hasFgColor &&
                            this->_stackBack().hasFgTrueColor) {
                        frame.setFgTrueColor(this->_stackBack().fgTrueColor);
                    }

                    if (!frame.hasBgTrueColor && !frame.hasBgColor &&
                            this->_stackBack().hasBgTrueColor) {
                        frame.setBgTrueColor(this->_stackBack().bgTrueColor);
                    }

                    if (!frame.hasFgColor && this->_stackBack().hasFgColor) {
                        frame.setFgColor(this->_stackBack().fgColorCodeOffset);
                    }

                    if (!frame.hasBgColor && this->_stackBack().hasBgColor) {
                        frame.setBgColor(this->_stackBack().bgColorCodeOffset);
                    }

                    this->_stackPush(frame, startAt);
                    this->_appendSgrCode(frame);
                }
            } else {
                /* Append regular character */
                _result += *_at;
                ++_at;
            }
        }

        /* Check for unbalanced tags */
        if (_stackLen > 1) {
            std::ostringstream ss;

            ss << "unbalanced opening tag: " << (_stackLen - 1) << " level(s) remain unclosed";
            this->_throw(ss.str());
        }
    }

private:
    const char *_begin;
    const char *_at;
    const char *_end;
    std::string _result;
    Stack _stack;
    Stack::size_type _stackLen = 0;
    bool _emitSgrCodes;
    bool _hasTrueColorSupport;
};

} /* namespace internal */

/*
 * Terminal support level for colors and attributes.
 */
enum class TerminalSupport
{
    /* No support for colors or attributes */
    None,

    /* Supports the ANSI 16-color palette and attributes */
    BasicColor,

    /* Supports true colors (24-bit) and attributes */
    TrueColor,
};

namespace internal {

/*
 * Returns whether or not the file descriptor `fd` is connected
 * to a terminal.
 */
inline bool isTerminal(const int fd) noexcept
{
    if (!isatty(fd)) {
        return false;
    }

    /* Verify the connected TTY is actually a character device */
    struct stat ttyStats;

    if (fstat(fd, &ttyStats) == 0 && !S_ISCHR(ttyStats.st_mode)) {
        return false;
    }

    return true;
}

/*
 * Returns the support level for colors and attributes of a terminal
 * according to the `TERM` and `COLORTERM` environment variables.
 */
inline TerminalSupport termSupport()
{
    /* Check if terminal explicitly doesn't support escape codes */
    const auto term = getEnv("TERM");

    if (term.empty() || term == "dumb") {
        return TerminalSupport::None;
    }

    /* Check for true color support via `COLORTERM` */
    const auto colorTerm = getEnv("COLORTERM");

    if (colorTerm == "truecolor" || colorTerm == "24bit" || colorTerm == "yes") {
        return TerminalSupport::TrueColor;
    }

    /* Check for true color support via `TERM` */
    if (endsWith(term, "-direct")) {
        return TerminalSupport::TrueColor;
    }

    /* Check for specific terminal emulators known to support true colors */
    if (term == "alacritty" || term == "xterm-kitty" || term == "wezterm" ||
            term == "foot" || term == "ghostty") {
        return TerminalSupport::TrueColor;
    }

    /* At this point, we have _at least_ basic color support */
    return TerminalSupport::BasicColor;
}

/*
 * Support level for colors and attributes according to the
 * environment variables.
 */
struct EnvSupport final
{
    TerminalSupport support;

    /* Whether or not `support` only applies to a terminal */
    bool needsTerminal;
};

/*
 * Returns the support level for colors and attributes according
 * to the `NO_COLOR`, `FORCE_COLOR`, `TERM`, and `COLORTERM`
 * environment variables.
 */
inline EnvSupport envSupport()
{
    /* See <https://no-color.org/> */
    if (!getEnv("NO_COLOR").empty()) {
        return {TerminalSupport::None, false};
    }

    const auto support = termSupport();

    /* See <https://force-color.org/> */
    if (!getEnv("FORCE_COLOR").empty()) {
        return {support == TerminalSupport::None ? TerminalSupport::BasicColor : support, false};
    }

    return {support, true};
}

} /* namespace internal */

/*
 * Returns the support level for colors and attributes of the terminal
 * connected to the file descriptor `fd`.
 *
 * The `TERM` and `COLORTERM` environment variables determine the
 * support level of a terminal. If `fd` isn't connected to a terminal,
 * then this function returns `TerminalSupport::None`.
 *
 * This function also honors the following environment variables when
 * they're set and not empty:
 *
 * `NO_COLOR` (see <https://no-color.org/>):
 *     This function returns `TerminalSupport::None`, whatever `fd`.
 *
 *     This variable takes precedence over `FORCE_COLOR`.
 *
 * `FORCE_COLOR` (see <https://force-color.org/>):
 *     This function returns the support level of a terminal, but at
 *     least `TerminalSupport::BasicColor`, even if `fd` isn't connected
 *     to a terminal.
 *
 * This function reads the environment variables once, the first time
 * you call it, but checks whether or not `fd` is connected to a
 * terminal on each call.
 *
 * This function is thread-safe and doesn't modify `errno`.
 */
inline TerminalSupport terminalSupport(const int fd = STDOUT_FILENO) noexcept
{
    const auto savedErrno = errno;
    static const auto env = internal::envSupport();
    const auto support = !env.needsTerminal || internal::isTerminal(fd) ?
                         env.support : TerminalSupport::None;

    errno = savedErrno;
    return support;
}

/*
 * When to emit SGR codes.
 */
enum class When
{
    /*
     * When the terminal connected to the file descriptor which you pass
     * to mint() seems to support it.
     *
     * In this mode, mint() only emits true color sequences
     * if the terminal seems to support it (terminalSupport()
     * returns `TerminalSupport::TrueColor`).
     *
     * This mode honors the `NO_COLOR` and `FORCE_COLOR` environment
     * variables (see terminalSupport()).
     */
    Auto,

    /*
     * Always, even if the connected terminal doesn't seem to
     * support it.
     *
     * In this mode, mint() always emits true color sequences.
     */
    Always,

    /*
     * Never, even if the connected terminal seems to support it.
     */
    Never,
};

namespace internal {

/*
 * Converts the string from `begin` to `end` (excluded) according to the
 * terminal support level `support`.
 */
inline std::string convert(const char * const begin, const char * const end,
                           const TerminalSupport support)
{
    Parser parser {
        begin, end,
        support != TerminalSupport::None,
        support == TerminalSupport::TrueColor,
    };

    return parser.takeStr();
}

} /* namespace internal */

/*
 * Parses the string from `begin` to `end` (excluded) for terminal
 * attribute tags, converts such tags to actual terminal SGR codes, and
 * returns the corresponding string.
 *
 * The `when` parameter controls when this function emits SGR codes:
 *
 * `When::Auto` (default):
 *     Only performs the conversion when the file descriptor `fd`
 *     (standard output by default) is connected to a terminal which
 *     seems to support colors and attributes.
 *
 *     When there's no terminal support (`terminalSupport(fd)` returns
 *     `TerminalSupport::None`), this function effectively removes
 *     attribute tags from the viewed string.
 *
 *     In this mode, this function only emits true color sequences
 *     if the terminal seems to support it (`terminalSupport(fd)`
 *     returns `TerminalSupport::TrueColor`).
 *
 *     A non-empty `NO_COLOR` environment variable disables the
 *     conversion, while a non-empty `FORCE_COLOR` one enables it even
 *     without a terminal. See terminalSupport() to learn more.
 *
 * `When::Always`:
 *     Always performs the conversion, even if the terminal doesn't seem
 *     to support it.
 *
 *     In this mode, this function always emits true color sequences.
 *
 * `When::Never`:
 *     Never performs the conversion and always removes attribute tags
 *     from the viewed string, even if the terminal seems to support it.
 *
 * This function ignores `fd`, `NO_COLOR`, and `FORCE_COLOR` unless
 * `when` is `When::Auto`.
 *
 * See the escapeAnsi() function to return to a plain string (without
 * SGR codes) from a string which this function returns.
 *
 * This function throws an instance of `std::runtime_error` when there's
 * a markup syntax error in the viewed string.
 *
 * This function is thread-safe and doesn't modify `errno`.
 *
 * MARKUP SYNTAX
 * ━━━━━━━━━━━━━
 * An opening tag is, between `[` and `]`, an unordered sequence of
 * specifiers (all optional, but at least one):
 *
 * `!`:
 *     Bold.
 *
 * `-`:
 *     Dim.
 *
 * `_`:
 *     Underline.
 *
 * `'`:
 *     Italic.
 *
 * `^`:
 *     Reverse video.
 *
 * `*`:
 *     Bright foreground color.
 *
 * `:COLOR` (background):
 * `COLOR` (foreground):
 *     `COLOR` is one of:
 *
 *     ANSI 16-color palette:
 *         ╔═════╦═════════╗
 *         ║ `d` ║ Default ║
 *         ║ `k` ║ Black   ║
 *         ║ `r` ║ Red     ║
 *         ║ `g` ║ Green   ║
 *         ║ `y` ║ Yellow  ║
 *         ║ `b` ║ Blue    ║
 *         ║ `m` ║ Magenta ║
 *         ║ `c` ║ Cyan    ║
 *         ║ `w` ║ White   ║
 *         ╚═════╩═════════╝
 *
 *     True color:
 *         `#` followed with six hex digits (like a CSS color).
 *
 *     Note that you can set two foreground or background colors within
 *     a single opening tag, for example:
 *
 *         A [r#e74c3c]wonderful [!:m:#9b59b6]day[//]!
 *
 *     If `when` is `When::Auto` and `terminalSupport(fd)` returns
 *     `TerminalSupport::BasicColor`, then this function will ignore the
 *     true colors and only keep the basic ones.
 *
 * Spaces are allowed between specifiers within an opening tag.
 *
 * A closing tag contains one or more `/` characters between `[` and
 * `]`. Each `/` closes one level.
 *
 * Escape `[` with `\[` and `\` with `\\`. Use escape() to escape text
 * for mint().
 *
 * Opening and closing tags may be nested (maximum four levels of depth)
 * and must be balanced. Note that nesting is additive: a nested tag
 * cannot cancel an active attribute.
 *
 * ┌───────────────────────────────────────────────────────────────┐
 * │ IMPORTANT: The SGR code of any opening and closing tag always │
 * │ starts with a reset.                                          │
 * └───────────────────────────────────────────────────────────────┘
 *
 * Examples:
 *
 *     This is [r]red text[/]
 *     [!]Bold[/] and [_]underlined[/] text
 *     Error: [!*r]critical failure[/]!
 *     To show [c_]cyan[/] text, use the `\[c]` tag
 *     [y:b]Yellow on blue background[/]
 *     A [#e74c3c]wonderful [!:#9b59b6]day[//]!
 *     Status: [!g]OK[/], Warning: [y*]attention[/]!
 *     Use [-]dim text[/] for less prominent information
 *     [^]Reversed colors[/] for emphasis
 *     [r]Level 1 [!]Level 2 [_]Level 3[///] back to default
 */
inline std::string mint(const char * const begin, const char * const end,
                        const When when = When::Auto, const int fd = STDOUT_FILENO)
{
    switch (when) {
    case When::Always:
        return internal::convert(begin, end, TerminalSupport::TrueColor);

    case When::Never:
        return internal::convert(begin, end, TerminalSupport::None);

    case When::Auto:
    default:
        return internal::convert(begin, end, terminalSupport(fd));
    }
}

/*
 * Overload with a C string.
 */
inline std::string mint(const char * const str, const When when = When::Auto,
                        const int fd = STDOUT_FILENO)
{
    return mint(str, str + std::strlen(str), when, fd);
}

/*
 * Overload with a C++ string.
 */
inline std::string mint(const std::string& str, const When when = When::Auto,
                        const int fd = STDOUT_FILENO)
{
    return mint(str.data(), str.data() + str.size(), when, fd);
}

/*
 * Like `mint(begin, end, when, fd)`, but emits SGR codes according to
 * the terminal support level `support`:
 *
 * `TerminalSupport::None`:
 *     Like `When::Never`: removes attribute tags.
 *
 * `TerminalSupport::BasicColor`:
 *     Performs the conversion, but ignores the true colors and only
 *     keeps the basic ones.
 *
 * `TerminalSupport::TrueColor`:
 *     Like `When::Always`.
 *
 * This is useful to decide yourself, for example according to a
 * command-line option:
 *
 *     const auto errSupport = colorOpt == "never" ?
 *                             mint::TerminalSupport::None :
 *                             mint::terminalSupport(STDERR_FILENO);
 *
 *     std::cerr << mint::mint("[!r]ERROR[/]: Cannot open file\n", errSupport);
 */
inline std::string mint(const char * const begin, const char * const end,
                        const TerminalSupport support)
{
    return internal::convert(begin, end, support);
}

/*
 * Overload with a C string.
 */
inline std::string mint(const char * const str, const TerminalSupport support)
{
    return mint(str, str + std::strlen(str), support);
}

/*
 * Overload with a C++ string.
 */
inline std::string mint(const std::string& str, const TerminalSupport support)
{
    return mint(str.data(), str.data() + str.size(), support);
}

/*
 * Returns a version of the string from `begin` to `end` (excluded)
 * with `[` characters replaced with `\[` and `\` characters replaced
 * with `\\`.
 */
inline std::string escape(const char * const begin,  const char * const end)
{
    std::string result;

    result.reserve(end - begin);

    for (auto at = begin; at != end; ++at) {
        if (*at == '\\') {
            result += "\\\\";
        } else if (*at == '[') {
            result += "\\[";
        } else {
            result += *at;
        }
    }

    return result;
}

/*
 * Overload with a C string.
 */
inline std::string escape(const char * const str)
{
    return escape(str, str + std::strlen(str));
}

/*
 * Overload with a C++ string.
 */
inline std::string escape(const std::string& str)
{
    return escape(str.data(), str.data() + str.size());
}

/*
 * Returns a version of the string from `begin` to `end` (excluded) with
 * all SGR escape codes removed.
 */
inline std::string escapeAnsi(const char * const begin, const char * const end)
{
    std::string result;

    result.reserve(end - begin);

    for (auto at = begin; at != end; ++at) {
        if (*at == '\033' && at + 1 < end && *(at + 1) == '[') {
            /* Found start of potential SGR sequence */
            auto scanAt = at + 2;

            /* Skip the parameters */
            while (scanAt < end && ((*scanAt >= '0' && *scanAt <= '9') ||
                                    *scanAt == ';' || *scanAt == ':')) {
                ++scanAt;
            }

            if (scanAt < end && *scanAt == 'm') {
                /* Found valid SGR sequence: skip it */
                at = scanAt;
            } else {
                /* Not an SGR sequence: keep it as is */
                result += *at;
            }
        } else {
            result += *at;
        }
    }

    return result;
}

/*
 * Overload with a C string.
 */
inline std::string escapeAnsi(const char * const str)
{
    return escapeAnsi(str, str + std::strlen(str));
}

/*
 * Overload with a C++ string.
 */
inline std::string escapeAnsi(const std::string& str)
{
    return escapeAnsi(str.data(), str.data() + str.size());
}

} /* namespace mint */

#endif /* MINT_HPP */
