/*
 * SPDX-FileCopyrightText: 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/dynamic-array.hpp>

void lttng_dynamic_array_init(struct lttng_dynamic_array *array,
			      size_t element_size,
			      lttng_dynamic_array_element_destructor destructor)
{
	lttng_dynamic_buffer_init(&array->buffer);
	array->element_size = element_size;
	array->size = 0;
	array->destructor = destructor;
}

int lttng_dynamic_array_set_count(struct lttng_dynamic_array *array, size_t new_element_count)
{
	int ret;

	if (!array) {
		ret = -1;
		goto end;
	}

	if (array->destructor) {
		size_t i;

		for (i = new_element_count; i < array->size; i++) {
			void *element = lttng_dynamic_array_get_element(array, i);

			array->destructor(element);
		}
	}

	array->size = new_element_count;
	ret = lttng_dynamic_buffer_set_size(&array->buffer,
					    new_element_count * array->element_size);
end:
	return ret;
}

int lttng_dynamic_array_add_element(struct lttng_dynamic_array *array, const void *element)
{
	int ret;

	if (!array || !element) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&array->buffer, element, array->element_size);
	if (ret) {
		goto end;
	}
	array->size++;
end:
	return ret;
}

int lttng_dynamic_array_remove_element(struct lttng_dynamic_array *array, size_t element_index)
{
	void *element = lttng_dynamic_array_get_element(array, element_index);

	if (array->destructor) {
		array->destructor(element);
	}
	if (element_index != lttng_dynamic_array_get_count(array) - 1) {
		void *next_element = lttng_dynamic_array_get_element(array, element_index + 1);

		memmove(element,
			next_element,
			(array->size - element_index - 1) * array->element_size);
	}
	array->size--;
	return lttng_dynamic_buffer_set_size(&array->buffer,
					     array->buffer.size - array->element_size);
}

void lttng_dynamic_array_reset(struct lttng_dynamic_array *array)
{
	if (array->destructor) {
		size_t i;

		for (i = 0; i < lttng_dynamic_array_get_count(array); i++) {
			array->destructor(lttng_dynamic_array_get_element(array, i));
		}
	}

	lttng_dynamic_buffer_reset(&array->buffer);
	array->size = 0;
}

void lttng_dynamic_array_clear(struct lttng_dynamic_array *array)
{
	if (array->destructor) {
		size_t i;

		for (i = 0; i < lttng_dynamic_array_get_count(array); i++) {
			array->destructor(lttng_dynamic_array_get_element(array, i));
		}
	}

	(void) lttng_dynamic_buffer_set_size(&array->buffer, 0);
	array->size = 0;
}

void lttng_dynamic_pointer_array_init(struct lttng_dynamic_pointer_array *array,
				      lttng_dynamic_pointer_array_destructor destructor)
{
	lttng_dynamic_array_init(&array->array, sizeof(void *), destructor);
}

int lttng_dynamic_pointer_array_remove_pointer(struct lttng_dynamic_pointer_array *array,
					       size_t index)
{
	int ret;
	const lttng_dynamic_array_element_destructor destructor = array->array.destructor;

	/*
	 * Prevent the destructor from being used by the underlying
	 * dynamic array.
	 */
	array->array.destructor = nullptr;
	if (destructor) {
		destructor(lttng_dynamic_pointer_array_get_pointer(array, index));
	}
	ret = lttng_dynamic_array_remove_element(&array->array, index);
	array->array.destructor = destructor;
	return ret;
}

/* Release any memory used by the dynamic array. */
void lttng_dynamic_pointer_array_reset(struct lttng_dynamic_pointer_array *array)
{
	if (array->array.destructor) {
		size_t i, count = lttng_dynamic_pointer_array_get_count(array);

		for (i = 0; i < count; i++) {
			void *ptr = lttng_dynamic_pointer_array_get_pointer(array, i);
			array->array.destructor(ptr);
		}
		/*
		 * Prevent the destructor from being used by the underlying
		 * dynamic array.
		 */
		array->array.destructor = nullptr;
	}
	lttng_dynamic_array_reset(&array->array);
}

void lttng_dynamic_pointer_array_clear(struct lttng_dynamic_pointer_array *array)
{
	const lttng_dynamic_array_element_destructor destructor = array->array.destructor;

	/*
	 * Prevent the destructor from being used by the underlying
	 * dynamic array.
	 */
	array->array.destructor = nullptr;
	if (destructor) {
		size_t i, count = lttng_dynamic_pointer_array_get_count(array);

		for (i = 0; i < count; i++) {
			void *ptr = lttng_dynamic_pointer_array_get_pointer(array, i);
			destructor(ptr);
		}
	}
	lttng_dynamic_array_clear(&array->array);
	array->array.destructor = destructor;
}
