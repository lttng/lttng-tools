#include "test-enum.h"

SS s;

enum myEnum {
ZERO,
ONE,
TWO,
FOUR = 4
};

enum
{
    NAMELESS_ENUM_ONE,
    NAMELESS_ENUM_TWO,
    NAMELESS_ENUM_THREE,
};

typedef enum
{
    TD_NAMELESS_ENUM_A,
    TD_NAMELESS_ENUM_B,
    TD_NAMELESS_ENUM_C,
} nameless_enum_type;