/*
 * Copyright (c) 2018, Linaro Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include <pkcs11.h>

#include "xtest_test.h"
#include "xtest_helpers.h"

static void xtest_tee_test_4101(ADBG_Case_t *c)
{
	CK_RV rv;

	rv = C_Initialize(NULL);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	rv = C_Finalize(NULL);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
		return;

	rv = C_Initialize(NULL);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	rv = C_Initialize(NULL);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==,
					CKR_CRYPTOKI_ALREADY_INITIALIZED);

	rv = C_Finalize(NULL);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
}

ADBG_CASE_DEFINE(regression, 4101, xtest_tee_test_4101,
		"Initialize and close Cryptoki library");
