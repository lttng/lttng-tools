/**
 * Copyright (C) 2023 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "common/time.hpp"

#include <stdio.h>

int main() {
   struct timespec t;
   int ret = lttng_clock_gettime(CLOCK_MONOTONIC, &t);
   if (ret == 0) {
      printf("%ld.%09ld\n", t.tv_sec, t.tv_nsec);
   }
   return ret;
}
