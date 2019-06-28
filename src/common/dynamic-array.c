/*
 * Copyright (C) 2019 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <common/dynamic-array.h>

LTTNG_HIDDEN
void lttng_dynamic_array_init(struct lttng_dynamic_array *array,
		size_t element_size,
		lttng_dynamic_array_element_destructor destructor)
{
	lttng_dynamic_buffer_init(&array->buffer);
	array->element_size = element_size;
	array->size = 0;
	array->destructor = destructor;
}

LTTNG_HIDDEN
int lttng_dynamic_array_add_element(struct lttng_dynamic_array *array,
		const void *element)
{
	int ret;

	if (!array || !element) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&array->buffer, element,
			array->element_size);
	if (ret) {
		goto end;
	}
	array->size++;
end:
	return ret;
}

LTTNG_HIDDEN
int lttng_dynamic_array_remove_element(struct lttng_dynamic_array *array,
		size_t element_index)
{
	void *element = lttng_dynamic_array_get_element(array,
			element_index);

	if (array->destructor) {
		array->destructor(element);
	}
	if (element_index != lttng_dynamic_array_get_count(array) - 1) {
		void *next_element = lttng_dynamic_array_get_element(array,
				element_index + 1);

		memmove(element, next_element,
				(array->size - element_index - 1) * array->element_size);
	}
	array->size--;
	return lttng_dynamic_buffer_set_size(&array->buffer,
			array->buffer.size - array->element_size);
}

LTTNG_HIDDEN
void lttng_dynamic_array_reset(struct lttng_dynamic_array *array)
{
	if (array->destructor) {
		size_t i;

		for (i = 0; i < lttng_dynamic_array_get_count(array); i++) {
			array->destructor(lttng_dynamic_array_get_element(array,
					i));
		}
	}

	lttng_dynamic_buffer_reset(&array->buffer);
	array->size = 0;
}

LTTNG_HIDDEN
void lttng_dynamic_pointer_array_init(
		struct lttng_dynamic_pointer_array *array,
		lttng_dynamic_pointer_array_destructor destructor)
{
	lttng_dynamic_array_init(&array->array, sizeof(void *), destructor);
}	

/* Release any memory used by the dynamic array. */
LTTNG_HIDDEN
void lttng_dynamic_pointer_array_reset(
		struct lttng_dynamic_pointer_array *array)
{
	if (array->array.destructor) {
		size_t i, count = lttng_dynamic_pointer_array_get_count(array);

		for (i = 0; i < count; i++) {
			void *ptr = lttng_dynamic_pointer_array_get_pointer(
					array, i);
			array->array.destructor(ptr);
		}
		array->array.destructor = NULL;
	}
	lttng_dynamic_array_reset(&array->array);
}
