/*
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_DYNAMIC_ARRAY_H
#define LTTNG_DYNAMIC_ARRAY_H

#include <common/dynamic-buffer.h>
#include <assert.h>

typedef void (*lttng_dynamic_array_element_destructor)(void *element);
typedef void (*lttng_dynamic_pointer_array_destructor)(void *ptr);

struct lttng_dynamic_array {
	struct lttng_dynamic_buffer buffer;
	size_t element_size;
	size_t size;
	lttng_dynamic_array_element_destructor destructor;
};

struct lttng_dynamic_pointer_array {
	struct lttng_dynamic_array array;
};

/*
 * Initialize a resizable array of fixed-size elements. This performs no
 * allocation and can't fail.
 */
LTTNG_HIDDEN
void lttng_dynamic_array_init(struct lttng_dynamic_array *array,
		size_t element_size,
		lttng_dynamic_array_element_destructor destructor);

/*
 * Returns the number of elements in the dynamic array.
 */
static inline
size_t lttng_dynamic_array_get_count(
		const struct lttng_dynamic_array *array)
{
	return array->size;
}

/*
 * Returns a pointer to the element. Mutating operations on the array invalidate
 * the returned pointer.
 */
static inline
void *lttng_dynamic_array_get_element(const struct lttng_dynamic_array *array,
		size_t element_index)
{
	assert(element_index < array->size);
	return array->buffer.data + (element_index * array->element_size);
}

/*
 * Set the array's element count to new_element_count. Any added element will
 * be zeroed.
 *
 * Be careful to expand the array's element count _before_ calling out external
 * APIs (e.g. read(3)) which may populate the buffer as setting the element
 * count after will zero-out the result of the operation.
 *
 * Shrinking an array does not zero the old content. If the buffer may contain
 * sensititve information, it must be cleared manually _before_ changing the
 * size.
 *
 * NOTE: It is striclty _invalid_ to access memory after _size_, regardless
 *       of prior calls to set_capacity().
 */
LTTNG_HIDDEN
int lttng_dynamic_array_set_count(struct lttng_dynamic_array *array,
		size_t new_element_count);

/*
 * Add an element to the end of a dynamic array. The array's element count is
 * increased by one and its underlying capacity is adjusted automatically.
 *
 * element is a pointer to the element to add (copy) to the array.
 */
LTTNG_HIDDEN
int lttng_dynamic_array_add_element(struct lttng_dynamic_array *array,
		const void *element);

/*
 * Remove an element from the dynamic array. The array's element count is
 * decreased by one and the following elements are shifted to take its place
 * (when applicable).
 */
LTTNG_HIDDEN
int lttng_dynamic_array_remove_element(struct lttng_dynamic_array *array,
		size_t element_index);

/* Release any memory used by the dynamic array. */
LTTNG_HIDDEN
void lttng_dynamic_array_reset(struct lttng_dynamic_array *array);

/* Remove all elements from the dynamic array. */
LTTNG_HIDDEN
void lttng_dynamic_array_clear(struct lttng_dynamic_array *array);

/*
 * Specialization of lttng_dynamic_array for pointers. This utility
 * is built under the assumption that pointer sizes are equal
 * for all data types on supported architectures. Revisit this in the event
 * of a port to an Harvard architecture.
 */

/*
 * Initialize a resizable array of fixed-size elements. This performs no
 * allocation and can't fail.
 */
LTTNG_HIDDEN
void lttng_dynamic_pointer_array_init(
		struct lttng_dynamic_pointer_array *array,
		lttng_dynamic_pointer_array_destructor destructor);

/*
 * Returns the number of pointers in the dynamic pointer array.
 */
static inline
size_t lttng_dynamic_pointer_array_get_count(
		const struct lttng_dynamic_pointer_array *array)
{
	return lttng_dynamic_array_get_count(&array->array);
}

/*
 * Returns the pointer at index `index`.
 */
static inline
void *lttng_dynamic_pointer_array_get_pointer(
		const struct lttng_dynamic_pointer_array *array, size_t index)
{
	void **element = lttng_dynamic_array_get_element(&array->array, index);

	return *element;
}

/*
 * Returns the pointer at index `index`, sets the array slot to NULL. Does not
 * run the destructor.
 */

static inline
void *lttng_dynamic_pointer_array_steal_pointer(
		struct lttng_dynamic_pointer_array *array, size_t index)
{
	void **p_element = lttng_dynamic_array_get_element(&array->array, index);
	void *element = *p_element;

	*p_element = NULL;

	return element;
}

/*
 * Add a pointer to the end of a dynamic pointer array. The array's element
 * count is increased by one and its underlying capacity is adjusted
 * automatically.
 */
static inline
int lttng_dynamic_pointer_array_add_pointer(
		struct lttng_dynamic_pointer_array *array, void *pointer)
{
	return lttng_dynamic_array_add_element(&array->array, &pointer);
}

/*
 * Remove a pointer from a dynamic pointer array. The array's element
 * count is decreased by one and the following pointers are shifted to
 * take the place of the removed pointer (if applicable).
 */
LTTNG_HIDDEN
int lttng_dynamic_pointer_array_remove_pointer(
		struct lttng_dynamic_pointer_array *array, size_t index);

/* Release any memory used by the dynamic array. */
LTTNG_HIDDEN
void lttng_dynamic_pointer_array_reset(
		struct lttng_dynamic_pointer_array *array);

/* Remove all elements from the dynamic pointer array. */
LTTNG_HIDDEN
void lttng_dynamic_pointer_array_clear(
		struct lttng_dynamic_pointer_array *array);

#endif /* LTTNG_DYNAMIC_ARRAY_H */
