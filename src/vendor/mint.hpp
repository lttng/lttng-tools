/*
 * Copyright (C) 2025 Philippe Proulx <eeppeliteloop@gmail.com>
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
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */

/*
 * This header offers mint::mint() v0.5.2, a C++ function which
 * transforms a string which can contain terminal attribute tags into
 * another string containing actual terminal SGR codes.
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
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace mint {
namespace internal {

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

    bool hasBold = false;
    bool hasDim = false;
    bool hasUnderline = false;
    bool hasItalic = false;
    bool hasBright = false;
    bool hasFgColor = false;
    std::uint8_t fgColorCodeOffset;
    bool hasBgColor = false;
    std::uint8_t bgColorCodeOffset;
};

using Stack = std::array<StackFrame, 5>;

/*
 * Helper for mint().
 *
 * Performs the conversion if `emitSgrCodes` is true at construction
 * time and makes the resulting string available as str().
 */
class Parser final
{
public:
    explicit Parser(const char * const begin, const char * const end, const bool emitSgrCodes) :
        _at {begin},
        _end {end},
        _emitSgrCodes {emitSgrCodes}
    {
        this->_parse();
    }

    std::string str() const
    {
        return _os.str();
    }

private:
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
        _os << "\033[0";

        if (frame.hasBold) {
            _os << ";1";
        }

        if (frame.hasDim) {
            _os << ";2";
        }

        if (frame.hasItalic) {
            _os << ";3";
        }

        if (frame.hasUnderline) {
            _os << ";4";
        }

        if (frame.hasFgColor) {
            _os << ';' << (frame.hasBright ? 90 : 30) + frame.fgColorCodeOffset;
        }

        if (frame.hasBgColor) {
            _os << ';' << 40 + frame.bgColorCodeOffset;
        }

        /* End of SGR code */
        _os << 'm';
    }

    /*
     * Tries to parse a color letter, returning the corresponding ANSI
     * color offset.
     *
     * Throws `std::runtime_error` on error.
     */
    std::uint8_t _tryParseColor()
    {
        if (_at == _end) {
            throw std::runtime_error {"Expecting color letter"};
        }

        const auto c = *_at;
        ++_at;

        switch (c) {
        case 'd':
            return 9;
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
        default:
            throw std::runtime_error {std::string {"Unknown color letter `"} + c + "`"};
        }
    }

    /*
     * Pushes `frame` onto the current stack.
     *
     * Throws `std::runtime_error` on error.
     */
    void _stackPush(const StackFrame& frame)
    {
        if (_stackLen >= _stack.size()) {
            throw std::runtime_error {"Maximum nesting depth exceeded"};
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
        assert(*_at == '[');
        ++_at;

        if (_at != _end && *_at == ']') {
            throw std::runtime_error {"Empty opening tag"};
        }

        /* Parse tag content flexibly */
        while (_at != _end && *_at != ']') {
            if (*_at == '!') {
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
            } else if (*_at == '#') {
                /* Italic */
                frame.hasItalic = true;
                ++_at;
            } else if (*_at == '*') {
                /* Bright foreground modifier */
                frame.hasBright = true;
                ++_at;
            } else if (*_at == ':') {
                /* Background color */
                ++_at;
                frame.setBgColor(this->_tryParseColor());
            } else {
                /* Foreground color */
                frame.setFgColor(this->_tryParseColor());
            }
        }

        /* Expect `]` */
        if (_at == _end || *_at != ']') {
            throw std::runtime_error {"Expecting `]` to terminate the opening tag"};
        }

        ++_at;
        return frame;
    }

    void _parse()
    {
        /* Initialize with default frame (no attributes) */
        this->_stackPush(StackFrame {});

        /* Read each character */
        while (_at != _end) {
            if (*_at == '\\') {
                /* Escape sequence */
                ++_at;

                if (_at == _end) {
                    throw std::runtime_error {"Incomplete escape sequence at end of string"};
                }

                if (*_at == '\\' || *_at == '[') {
                    _os << *_at;
                    ++_at;
                } else {
                    throw std::runtime_error {"Invalid escape sequence"};
                }
            } else if (*_at == '[') {
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
                        throw std::runtime_error {"Expecting `]` after `[/`"};
                    }

                    /* Validate we have enough frames to pop */
                    if (_stackLen <= slashCount) {
                        throw std::runtime_error {"Unbalanced closing tag"};
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

                    if (!frame.hasBright && this->_stackBack().hasBright) {
                        frame.hasBright = true;
                    }

                    if (!frame.hasFgColor && this->_stackBack().hasFgColor) {
                        frame.setFgColor(this->_stackBack().fgColorCodeOffset);
                    }

                    if (!frame.hasBgColor && this->_stackBack().hasBgColor) {
                        frame.setBgColor(this->_stackBack().bgColorCodeOffset);
                    }

                    this->_stackPush(frame);
                    this->_appendSgrCode(frame);
                }
            } else {
                /* Append regular character */
                _os << *_at;
                ++_at;
            }
        }

        /* Check for unbalanced tags */
        if (_stackLen > 1) {
            throw std::runtime_error {"Unbalanced opening tag"};
        }
    }

private:
    const char *_at;
    const char *_end;
    std::ostringstream _os;
    Stack _stack;
    Stack::size_type _stackLen = 0;
    bool _emitSgrCodes;
};

} /* namespace internal */

/*
 * Returns whether or not there's a connected terminal which seems to
 * support attributes.
 *
 * This function is thread-safe and doesn't modify `errno`.
 */
inline bool hasTerminalSupport() noexcept
{
    static std::once_flag initFlag;
    static bool hasSupport;
    const auto savedErrno = errno;

    std::call_once(initFlag, [] {
        /* Check if standard output is connected to a real TTY */
        if (!isatty(STDOUT_FILENO)) {
            hasSupport = false;
            return;
        }

        /* Verify the connected TTY is actually a character device */
        {
            struct stat ttyStats;

            if (fstat(STDOUT_FILENO, &ttyStats) == 0) {
                if (!S_ISCHR(ttyStats.st_mode)) {
                    /* Not a character device */
                    hasSupport = false;
                    return;
                }
            }
        }

        /* Check if terminal explicitly doesn't support escape codes */
        {
            const auto term = std::getenv("TERM");

            if (!term || std::strcmp(term, "dumb") == 0) {
                hasSupport = false;
                return;
            }
        }

        hasSupport = true;
    });

    errno = savedErrno;
    return hasSupport;
}

/*
 * When to emit SGR codes.
 */
enum class When
{
    /* When the connected terminal seems to supports it */
    Auto,

    /* Always, even if the connected terminal doesn't seem to support it */
    Always,

    /* Never, even if the connected terminal seems to support it */
    Never,
};

/*
 * Parses the string from `begin` to `end` (excluded) for terminal
 * attribute tags, converts such tags to actual terminal SGR codes, and
 * returns the corresponding string.
 *
 * The `when` parameter controls when this function emits SGR codes:
 *
 * `When::Auto` (default):
 *     Only performs the conversion when there's a connected terminal
 *     which seems to support attributes.
 *
 *     When there's no terminal SGR support (hasTerminalSupport()
 *     returns false), this function effectively removes attribute tags
 *     from the viewed string.
 *
 * `When::Always`:
 *     Always performs the conversion, even if the connected terminal
 *     doesn't seem to support it.
 *
 * `When::Never`:
 *     Never performs the conversion and always removes attribute tags
 *     from the viewed string, even if the connected terminal seems to
 *     support it.
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
 * An opening tag is, between `[` and `]`, an unordered sequence of (all
 * optional, but at least one):
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
 * `#`:
 *     Italic.
 *
 * `*`:
 *     Bright foreground color.
 *
 * `:COLOR` (background):
 * `COLOR` (foreground):
 *     `COLOR` is one of:
 *
 *     ╔═════╦═════════╗
 *     ║ `d` ║ Default ║
 *     ║ `k` ║ Black   ║
 *     ║ `r` ║ Red     ║
 *     ║ `g` ║ Green   ║
 *     ║ `y` ║ Yellow  ║
 *     ║ `b` ║ Blue    ║
 *     ║ `m` ║ Magenta ║
 *     ║ `c` ║ Cyan    ║
 *     ║ `w` ║ White   ║
 *     ╚═════╩═════════╝
 *
 * A closing tag contains one or more `/` characters between
 * `[` and `]`. Each `/` closes one level.
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
 *     Status: [!g]OK[/], Warning: [y*]attention[/]!
 *     Use [-]dim text[/] for less prominent information
 *     [r]Level 1 [!]Level 2 [_]Level 3[///] back to default
 */
inline std::string mint(const char * const begin, const char * const end, const When when = When::Auto)
{
    internal::Parser parser {
        begin, end,
        when == When::Always || (when == When::Auto && hasTerminalSupport())
    };

    return parser.str();
}

/*
 * Overload with a C string.
 */
inline std::string mint(const char * const str, const When when = When::Auto)
{
    return mint(str, str + std::strlen(str), when);
}

/*
 * Overload with a C++ string.
 */
inline std::string mint(const std::string& str, const When when = When::Auto)
{
    return mint(str.data(), str.data() + str.size(), when);
}

/*
 * Returns a version of the string from `begin` to `end` (excluded) with
 * `[` characters replaced with `\[` and `\` characters replaced
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

            /* Skip until we find 'm' or reach end */
            while (scanAt < end && *scanAt != 'm') {
                ++scanAt;
            }

            if (scanAt < end && *scanAt == 'm') {
                /* Found valid SGR sequence: skip it */
                at = scanAt;
            } else {
                /* Not a valid SGR sequence: keep the escape char. */
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
