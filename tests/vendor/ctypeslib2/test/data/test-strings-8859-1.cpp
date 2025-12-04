// This file contains a mix of ISO-8859-1 and UTF-8 encoded data.
// the literal assigned to 'aa' should be the ISO-8859-1 encoding for the code
// points U+00C0 U+00E9 U+00EE U+00F5 U+00FC

// The rest of the literals should contain the UTF-8 encoding for U+041A U+043E
// U+0448 U+043A U+0430
#include <stddef.h>
// CHECK-C: private unnamed_addr constant [6 x i8] c"\C0\E9\EE\F5\FC\00", align 1
// CHECK-CPP0X: private unnamed_addr constant [6 x i8] c"\C0\E9\EE\F5\FC\00", align 1
char const *aa = "Àéîõü";
