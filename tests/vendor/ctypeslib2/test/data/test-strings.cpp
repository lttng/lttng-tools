// This file contains a mix of ISO-8859-1 and UTF-8 encoded data.
// the literal assigned to 'aa' should be the ISO-8859-1 encoding for the code
// points U+00C0 U+00E9 U+00EE U+00F5 U+00FC

// The rest of the literals should contain the UTF-8 encoding for U+041A U+043E
// U+0448 U+043A U+0430
#include <stddef.h>
// CHECK-C: private unnamed_addr constant [6 x i8] c"\C0\E9\EE\F5\FC\00", align 1
// CHECK-CPP0X: private unnamed_addr constant [6 x i8] c"\C0\E9\EE\F5\FC\00", align 1

// CHECK-C: private unnamed_addr constant [11 x i8] c"\D0\9A\D0\BE\D1\88\D0\BA\D0\B0\00", align 1
// CHECK-CPP0X: private unnamed_addr constant [11 x i8] c"\D0\9A\D0\BE\D1\88\D0\BA\D0\B0\00", align 1
char const *a = "Кошка";

// CHECK-C: private unnamed_addr constant [6 x i32] [i32 1050, i32 1086, i32 1096, i32 1082, i32 1072, i32 0], align 4
// CHECK-SHORTWCHAR: private unnamed_addr constant [6 x i16] [i16 1050, i16 1086, i16 1096, i16 1082, i16 1072, i16 0], align 2
// CHECK-CPP0X: private unnamed_addr constant [6 x i32] [i32 1050, i32 1086, i32 1096, i32 1082, i32 1072, i32 0], align 4
wchar_t const *b = L"Кошка";

// CHECK-C: private unnamed_addr constant [4 x i32] [i32 20320, i32 22909, i32 66304, i32 0], align 4
// CHECK-SHORTWCHAR: private unnamed_addr constant [4 x i16] [i16 20320, i16 22909, i16 768, i16 0], align 2
// CHECK-CPP0X: private unnamed_addr constant [4 x i32] [i32 20320, i32 22909, i32 66304, i32 0], align 4
wchar_t const *b2 = L"\x4f60\x597d\x10300"; // '\u4f60\u597d\U00010300'

// next tests are C++11 only

// CHECK-CPP0X: private unnamed_addr constant [12 x i8] c"1\D0\9A\D0\BE\D1\88\D0\BA\D0\B0\00", align 1
char const *c = u8"1Кошка";

// CHECK-CPP0X: private unnamed_addr constant [12 x i8] c"4\D0\9A\D0\BE\D1\88\D0\BA\D0\B0\00", align 1
char const *d = u8R"(4Кошка)";

// CHECK-CPP0X: private unnamed_addr constant [7 x i16] [i16 50, i16 1050, i16 1086, i16 1096, i16 1082, i16 1072, i16 0], align 2
char16_t const *e = u"2Кошка";

// CHECK-CPP0X: private unnamed_addr constant [7 x i32] [i32 51, i32 1050, i32 1086, i32 1096, i32 1082, i32 1072, i32 0], align 4
char32_t const *f = U"3Кошка";

// CHECK-CPP0X: private unnamed_addr constant [7 x i16] [i16 53, i16 1050, i16 1086, i16 1096, i16 1082, i16 1072, i16 0], align 2
char16_t const *g = uR"(5Кошка)";

// CHECK-CPP0X: private unnamed_addr constant [7 x i32] [i32 54, i32 1050, i32 1086, i32 1096, i32 1082, i32 1072, i32 0], align 4
char32_t const *h = UR"(6Кошка)";

// CHECK-SHORTWCHAR: private unnamed_addr constant [7 x i16] [i16 55, i16 1050, i16 1086, i16 1096, i16 1082, i16 1072, i16 0], align 2
// CHECK-CPP0X: private unnamed_addr constant [7 x i32] [i32 55, i32 1050, i32 1086, i32 1096, i32 1082, i32 1072, i32 0], align 4
wchar_t const *i = LR"(7Кошка)";


