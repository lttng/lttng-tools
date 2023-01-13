/*
 * Copyright (C) 2010-2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "tsdl-environment-visitor.hpp"
#include "ust-app.hpp"
#include "ust-clock-class.hpp"
#include "ust-registry.hpp"

#include <common/common.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/time.hpp>
#include <common/uuid.hpp>

#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <vector>

namespace ls = lttng::sessiond;
namespace lsu = lttng::sessiond::ust;
