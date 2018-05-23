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

#include <inttypes.h>
#include <malloc.h>
#include <pkcs11.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xtest_test.h"
#include "xtest_helpers.h"

/*
 * Util to find a slot on which to open a session
 */
static CK_RV close_lib(void)
{
	return C_Finalize(0);
}

static CK_RV init_lib_and_find_token_slot(CK_SLOT_ID *slot)
{
	CK_RV rv;
	CK_SLOT_ID_PTR slots = NULL;
	CK_ULONG count;

	rv = C_Initialize(0);
	if (rv)
		return rv;

	rv = C_GetSlotList(CK_TRUE, NULL, &count);
	if (rv != CKR_BUFFER_TOO_SMALL)
		goto bail;

	if (count < 1) {
		rv = CKR_GENERAL_ERROR;
		goto bail;
	}

	slots = malloc(count * sizeof(CK_SLOT_ID));
	if (!slots) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = C_GetSlotList(CK_TRUE, slots, &count);
	if (rv)
		goto bail;

	/* Use the 1st slot */
	*slot = *slots;

bail:
	free(slots);
	if (rv)
		close_lib();

	return rv;
}

static void xtest_tee_test_4101(ADBG_Case_t *c)
{
	CK_RV rv;

	rv = C_Initialize(NULL);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	rv = C_Finalize(NULL);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
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

static void xtest_tee_test_4102(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID_PTR slot_ids = NULL;
	CK_ULONG slot_count;
	CK_ULONG slot_count2;
	CK_INFO lib_info;
	CK_SLOT_INFO slot_info;
	CK_TOKEN_INFO token_info;
	CK_FUNCTION_LIST_PTR ckfunc_list;
	size_t i;
	size_t j;
	CK_MECHANISM_TYPE_PTR mecha_types = NULL;

	rv = C_Initialize(NULL);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	rv = C_GetInfo(&lib_info);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto out;

	rv = C_GetFunctionList(&ckfunc_list);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto out;

	slot_count2 = 0;
	rv = C_GetSlotList(0, NULL, &slot_count2);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_BUFFER_TOO_SMALL))
		goto out;

	slot_count = 0;

	rv = C_GetSlotList(1, NULL, &slot_count);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_BUFFER_TOO_SMALL))
		goto out;

	slot_ids = calloc(slot_count, sizeof(CK_SLOT_ID));
	if (!ADBG_EXPECT_TRUE(c, !slot_count || slot_ids))
		goto out;

	rv = C_GetSlotList(1, slot_ids, &slot_count);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto out;

	for (i = 0; i < slot_count; i++) {
		CK_SLOT_ID slot = *(slot_ids + i);
		CK_ULONG mecha_count;

		rv = C_GetSlotInfo(slot, &slot_info);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto out;

		rv = C_GetTokenInfo(slot, &token_info);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto out;

		mecha_count = 0;
		rv = C_GetMechanismList(slot, NULL, &mecha_count);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==,
						  CKR_BUFFER_TOO_SMALL))
			goto out;

		mecha_types = calloc(mecha_count, sizeof(CK_MECHANISM_TYPE));
		if (!ADBG_EXPECT_TRUE(c, !mecha_count || mecha_types))
			goto out;

		rv = C_GetMechanismList(slot, mecha_types, &mecha_count);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto out;

		for (j = 0; j < mecha_count; j++) {
			CK_MECHANISM_TYPE type = *(mecha_types + j);
			CK_MECHANISM_INFO mecha_info;

			rv = C_GetMechanismInfo(slot, type, &mecha_info);
			if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
				goto out;
		}

		free(mecha_types);
		mecha_types = NULL;
	}

out:
	free(slot_ids);
	free(mecha_types);

	rv = C_Finalize(NULL);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
}

static void xtest_tee_test_4103(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot = 0;
	CK_TOKEN_INFO token_info;
	char pin0[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
	char pin1[] = { 0, 1, 2, 3, 0, 5, 6, 7, 8, 9, 10 };
	char pin2[] = { 0, 1, 2, 3, 4, 5, 6, 0, 8 };
	char label[] = "sks test token";
	char label32[32];

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	rv = C_GetTokenInfo(slot, &token_info);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	if (strlen(label) < 32) {
		int sz = strlen(label);

		memcpy(label32, label, sz);
		memset(&label32[sz], ' ', 32 - sz);
	} else {
		memcpy(label32, label, 32);
	}

	if (token_info.flags & CKF_TOKEN_INITIALIZED) {

		// "Token is already initialized.\n"
		// TODO: skip this if token is about to lock

		rv = C_InitToken(slot, (CK_UTF8CHAR_PTR)pin1, sizeof(pin1),
				 (CK_UTF8CHAR_PTR)label32);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
			goto bail;


		rv = C_InitToken(slot, (CK_UTF8CHAR_PTR)pin2, sizeof(pin2),
				 (CK_UTF8CHAR_PTR)label32);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
			goto bail;

		rv = C_GetTokenInfo(slot, &token_info);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto bail;

		/* Token should have set CKF_SO_PIN_COUNT_LOW to 1 */
		if (!ADBG_EXPECT_TRUE(c, !!(token_info.flags &
						CKF_SO_PIN_COUNT_LOW))) {
			rv = CKR_GENERAL_ERROR;
			goto bail;
		}

		rv = C_InitToken(slot, (CK_UTF8CHAR_PTR)pin0, sizeof(pin0),
				 (CK_UTF8CHAR_PTR)label32);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto bail;

		rv = C_GetTokenInfo(slot, &token_info);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto bail;

		/*
		 * Token should have reset CKF_SO_PIN_COUNT_LOW to 0.
		 * Other flags should show a sane initialized state.
		 */
		if (!ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_SO_PIN_COUNT_LOW)) ||
		    !ADBG_EXPECT_TRUE(c, !!(token_info.flags &
						CKF_TOKEN_INITIALIZED)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_ERROR_STATE)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_USER_PIN_INITIALIZED))) {
			rv = CKR_GENERAL_ERROR;
			goto bail;
		}
	} else {
		//("Token was not yet initialized.\n");
		/*  We must provision the SO PIN */

		rv = C_InitToken(slot, (CK_UTF8CHAR_PTR)pin0, sizeof(pin0),
				 (CK_UTF8CHAR_PTR)label32);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto bail;

		rv = C_GetTokenInfo(slot, &token_info);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto bail;

		if (!ADBG_EXPECT_TRUE(c, !!(token_info.flags &
						CKF_TOKEN_INITIALIZED)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_ERROR_STATE)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_USER_PIN_INITIALIZED))) {
			rv = CKR_GENERAL_ERROR;
			goto bail;
		}
	}

bail:
	rv = close_lib();
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
}

static void xtest_tee_test_4104(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session[3];
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	/* Open 3 sessions */
	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[0]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[1]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[2]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	/* Close 2 of them */
	rv = C_CloseSession(session[0]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_CloseSession(session[1]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	/* Close all remaing sessions */
	rv = C_CloseAllSessions(slot);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	/* Should failed to close non existing session */
	rv = C_CloseSession(session[2]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
		goto bail;

	/* Last open/closure of a session */
	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[0]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_CloseSession(session[0]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[1]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

bail:
	rv = close_lib();
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
}

ADBG_CASE_DEFINE(regression, 4101, xtest_tee_test_4101,
		"Initialize and close Cryptoki library");
ADBG_CASE_DEFINE(regression, 4102, xtest_tee_test_4102,
		"Connect token and get some token info");
ADBG_CASE_DEFINE(regression, 4103, xtest_tee_test_4103,
		"Login tests (TODO: still weak)");
ADBG_CASE_DEFINE(regression, 4104, xtest_tee_test_4104,
		"Open and close PKCS#11 sessions");
