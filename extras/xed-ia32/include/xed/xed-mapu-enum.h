/*BEGIN_LEGAL 
Copyright 2002-2020 Intel Corporation.

This software and the related documents are Intel copyrighted materials, and your
use of them is governed by the express license under which they were provided to
you ("License"). Unless the License provides otherwise, you may not use, modify,
copy, publish, distribute, disclose or transmit this software or the related
documents without Intel's prior written permission.

This software and the related documents are provided as is, with no express or
implied warranties, other than those that are expressly stated in the License.
END_LEGAL */
/// @file xed-mapu-enum.h

// This file was automatically generated.
// Do not edit this file.

#if !defined(XED_MAPU_ENUM_H)
# define XED_MAPU_ENUM_H
#include "xed-common-hdrs.h"
#define XED_MAPU_INVALID_DEFINED 1
#define XED_MAPU_AMD_3DNOW_DEFINED 1
#define XED_MAPU_AMD_XOP8_DEFINED 1
#define XED_MAPU_AMD_XOP9_DEFINED 1
#define XED_MAPU_AMD_XOPA_DEFINED 1
#define XED_MAPU_EVEX_MAP1_DEFINED 1
#define XED_MAPU_EVEX_MAP2_DEFINED 1
#define XED_MAPU_EVEX_MAP3_DEFINED 1
#define XED_MAPU_LEGACY_MAP0_DEFINED 1
#define XED_MAPU_LEGACY_MAP1_DEFINED 1
#define XED_MAPU_LEGACY_MAP2_DEFINED 1
#define XED_MAPU_LEGACY_MAP3_DEFINED 1
#define XED_MAPU_VEX_MAP1_DEFINED 1
#define XED_MAPU_VEX_MAP2_DEFINED 1
#define XED_MAPU_VEX_MAP3_DEFINED 1
#define XED_MAPU_LAST_DEFINED 1
typedef enum {
  XED_MAPU_INVALID,
  XED_MAPU_AMD_3DNOW,
  XED_MAPU_AMD_XOP8,
  XED_MAPU_AMD_XOP9,
  XED_MAPU_AMD_XOPA,
  XED_MAPU_EVEX_MAP1,
  XED_MAPU_EVEX_MAP2,
  XED_MAPU_EVEX_MAP3,
  XED_MAPU_LEGACY_MAP0,
  XED_MAPU_LEGACY_MAP1,
  XED_MAPU_LEGACY_MAP2,
  XED_MAPU_LEGACY_MAP3,
  XED_MAPU_VEX_MAP1,
  XED_MAPU_VEX_MAP2,
  XED_MAPU_VEX_MAP3,
  XED_MAPU_LAST
} xed_mapu_enum_t;

/// This converts strings to #xed_mapu_enum_t types.
/// @param s A C-string.
/// @return #xed_mapu_enum_t
/// @ingroup ENUM
XED_DLL_EXPORT xed_mapu_enum_t str2xed_mapu_enum_t(const char* s);
/// This converts strings to #xed_mapu_enum_t types.
/// @param p An enumeration element of type xed_mapu_enum_t.
/// @return string
/// @ingroup ENUM
XED_DLL_EXPORT const char* xed_mapu_enum_t2str(const xed_mapu_enum_t p);

/// Returns the last element of the enumeration
/// @return xed_mapu_enum_t The last element of the enumeration.
/// @ingroup ENUM
XED_DLL_EXPORT xed_mapu_enum_t xed_mapu_enum_t_last(void);
#endif
