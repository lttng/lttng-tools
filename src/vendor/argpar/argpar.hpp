/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2024 Simon Marchi <simon.marchi@efficios.com>
 */

#ifndef ARGPAR_HPP
#define ARGPAR_HPP

#include <cstdlib>
#include <exception>
#include <memory>

#include "argpar.h"

namespace argpar {

template <typename OptionalItemT>
class Iter;

class Error : public std::exception
{
    template <typename OptionalItemT>
    friend class Iter;

protected:
    explicit Error(const argpar_error& error) noexcept : _mError {&error}

    {
    }

public:
    unsigned int origIndex() const noexcept
    {
        return argpar_error_orig_index(_mError.get());
    }

private:
    struct _Deleter final
    {
        void operator()(const argpar_error *error)
        {
            argpar_error_destroy(error);
        }
    };

protected:
    std::unique_ptr<const argpar_error, _Deleter> _mError;
};

class UnknownOptError final : public Error
{
    template <typename OptionalItemT>
    friend class Iter;

private:
    explicit UnknownOptError(const argpar_error& error) noexcept : Error {error}
    {
    }

public:
    const char *name() const noexcept
    {
        return argpar_error_unknown_opt_name(_mError.get());
    }
};

class OptArgError;

class OptArgErrorDescr final
{
    friend class OptArgError;

private:
    explicit OptArgErrorDescr(const argpar_opt_descr_t& descr, const bool isShort) noexcept :
        _mDescr {&descr}, _mIsShort {isShort}
    {
    }

public:
    const argpar_opt_descr_t& descr() const noexcept
    {
        return *_mDescr;
    }

    bool isShort() const noexcept
    {
        return _mIsShort;
    }

private:
    const argpar_opt_descr_t *_mDescr;
    bool _mIsShort;
};

class OptArgError : public Error
{
protected:
    explicit OptArgError(const argpar_error& error) : Error {error}
    {
    }

public:
    OptArgErrorDescr descr() const noexcept
    {
        bool isShort;
        auto& descr = *argpar_error_opt_descr(_mError.get(), &isShort);

        return OptArgErrorDescr {descr, isShort};
    }
};

class MissingOptArgumentError final : public OptArgError
{
    template <typename OptionalItemT>
    friend class Iter;

private:
    explicit MissingOptArgumentError(const argpar_error& error) noexcept : OptArgError {error}
    {
    }
};

class UnexpectedOptArgumentError final : public OptArgError
{
    template <typename OptionalItemT>
    friend class Iter;

private:
    explicit UnexpectedOptArgumentError(const argpar_error& error) noexcept : OptArgError {error}
    {
    }
};

namespace internal {

struct ArgparItemDeleter final
{
    void operator()(const argpar_item_t * const item) const noexcept
    {
        argpar_item_destroy(item);
    }
};

using ArgparItemUP = std::unique_ptr<const argpar_item_t, ArgparItemDeleter>;

} /* namespace internal */

class OptItemView;
class NonOptItemView;

class Item
{
    template <typename OptionalItemT>
    friend class Iter;

public:
    enum class Type
    {
        Opt = ARGPAR_ITEM_TYPE_OPT,
        NonOpt = ARGPAR_ITEM_TYPE_NON_OPT,
    };

protected:
    explicit Item(internal::ArgparItemUP item) : _mItem {std::move(item)}
    {
    }

public:
    bool isOpt() const noexcept
    {
        return this->type() == Type::Opt;
    }

    bool isNonOpt() const noexcept
    {
        return this->type() == Type::NonOpt;
    }

    OptItemView asOpt() const noexcept;
    NonOptItemView asNonOpt() const noexcept;

    Type type() const noexcept
    {
        return static_cast<Type>(argpar_item_type(_mItem.get()));
    }

protected:
    internal::ArgparItemUP _mItem;
};

namespace internal {

class ItemView
{
protected:
    explicit ItemView(const argpar_item_t& item) : _mItem {&item}
    {
    }

    const argpar_item_t *_mItem;
};

}; // namespace internal

class OptItemView final : private internal::ItemView
{
    friend class Item;

private:
    explicit OptItemView(const argpar_item_t& item) : internal::ItemView {item}
    {
    }

public:
    const argpar_opt_descr_t& descr() const noexcept
    {
        return *argpar_item_opt_descr(_mItem);
    }

    const char *arg() const noexcept
    {
        return argpar_item_opt_arg(_mItem);
    }
};

inline OptItemView Item::asOpt() const noexcept
{
    return OptItemView {*_mItem};
}

class NonOptItemView final : public internal::ItemView
{
    friend class Item;

private:
    explicit NonOptItemView(const argpar_item_t& item) : internal::ItemView {item}
    {
    }

public:
    const char *arg() const noexcept
    {
        return argpar_item_non_opt_arg(_mItem);
    }

    unsigned int origIndex() const noexcept
    {
        return argpar_item_non_opt_orig_index(_mItem);
    }

    unsigned int nonOptIndex() const noexcept
    {
        return argpar_item_non_opt_non_opt_index(_mItem);
    }
};

inline NonOptItemView Item::asNonOpt() const noexcept
{
    return NonOptItemView {*_mItem};
}

template <typename OptionalItemT>
class Iter final
{
    static_assert(std::is_default_constructible<OptionalItemT>::value,
                  "`OptionalItemT` has a callable default constructor.");
    static_assert(std::is_constructible<OptionalItemT, Item&&>::value,
                  "`OptionalItemT::OptionalItemT(argpar::Item&&)` is callable.");

public:
    explicit Iter(const unsigned int argc, const char * const * const argv,
                  const argpar_opt_descr_t * const descrs) :
        _mIter {[&] {
            if (const auto iter = argpar_iter_create(argc, argv, descrs)) {
                return iter;
            }

            throw std::bad_alloc {};
        }()}
    {
    }

    OptionalItemT next()
    {
        const argpar_item_t *item;
        const argpar_error_t *error;

        switch (argpar_iter_next(_mIter.get(), &item, &error)) {
        case ARGPAR_ITER_NEXT_STATUS_OK:
            return OptionalItemT {Item {internal::ArgparItemUP {item}}};

        case ARGPAR_ITER_NEXT_STATUS_END:
            return OptionalItemT {};

        case ARGPAR_ITER_NEXT_STATUS_ERROR:
            switch (argpar_error_type(error)) {
            case ARGPAR_ERROR_TYPE_UNKNOWN_OPT:
                throw UnknownOptError {*error};

            case ARGPAR_ERROR_TYPE_MISSING_OPT_ARG:
                throw MissingOptArgumentError {*error};

            case ARGPAR_ERROR_TYPE_UNEXPECTED_OPT_ARG:
                throw UnexpectedOptArgumentError {*error};
            }

            std::abort();

        case ARGPAR_ITER_NEXT_STATUS_ERROR_MEMORY:
            throw std::bad_alloc {};
        }

        std::abort();
    }

    unsigned int ingestedOrigArgs() const noexcept
    {
        return argpar_iter_ingested_orig_args(_mIter.get());
    }

private:
    struct _IterDeleter final
    {
        void operator()(argpar_iter_t * const iter) const noexcept
        {
            argpar_iter_destroy(iter);
        }
    };

    std::unique_ptr<argpar_iter, _IterDeleter> _mIter;
};

} /* namespace argpar */

#endif /* ARGPAR_HPP */
