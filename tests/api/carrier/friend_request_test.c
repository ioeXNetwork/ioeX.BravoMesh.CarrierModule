/*
 * 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <CUnit/Basic.h>

#include "IOEX_carrier.h"
#include "cond.h"
#include "tests.h"
#include "test_helper.h"

struct CarrierContextExtra {
    char* from;

    // for friend request
    IOEXUserInfo info;
    char* hello;
    int len;

    IOEXConnectionStatus connection_status;
};

static CarrierContextExtra extra = {
    .from   = NULL,

    .hello  = NULL,
    .len    = 0,

    .connection_status = IOEXConnectionStatus_Disconnected
};

static inline void wakeup(void* context)
{
    cond_signal(((CarrierContext *)context)->cond);
}

static void ready_cb(IOEXCarrier *w, void *context)
{
    cond_signal(((CarrierContext *)context)->ready_cond);
}

static
void friend_added_cb(IOEXCarrier *w, const IOEXFriendInfo *info, void *context)
{
    wakeup(context);
    test_log_debug("Friend %s added.\n", info->user_info.userid);
}

static void friend_removed_cb(IOEXCarrier *w, const char *friendid, void *context)
{
    wakeup(context);
    test_log_debug("Friend %s removed.\n", friendid);
}

static void friend_connection_cb(IOEXCarrier *w, const char *friendid,
                                 IOEXConnectionStatus status, void *context)
{
    CarrierContext *wctxt = (CarrierContext *)context;

    wakeup(context);

    wctxt->extra->connection_status = status;
    wctxt->robot_online = (status == IOEXConnectionStatus_Connected);

    test_log_debug("Robot connection status changed -> %s\n",
                    connection_str(status));
}

static
void friend_request_cb(IOEXCarrier *w, const char *userid, const IOEXUserInfo *info,
                       const char *hello, void* context)
{
    CarrierContextExtra *extra = ((CarrierContext *)context)->extra;

    extra->from  = strdup(userid);
    extra->hello = strdup(hello);
    memcpy(&extra->info, info, sizeof(*info));

    wakeup(context);
}

static IOEXCallbacks callbacks = {
    .idle            = NULL,
    .connection_status = NULL,
    .ready           = ready_cb,
    .self_info       = NULL,
    .friend_list     = NULL,
    .friend_connection = friend_connection_cb,
    .friend_info     = NULL,
    .friend_presence = NULL,
    .friend_request  = friend_request_cb,
    .friend_added    = friend_added_cb,
    .friend_removed  = friend_removed_cb,
    .friend_message  = NULL,
    .friend_invite   = NULL
};

static Condition DEFINE_COND(ready_cond);
static Condition DEFINE_COND(cond);

static CarrierContext carrier_context = {
    .cbs = &callbacks,
    .carrier = NULL,
    .ready_cond = &ready_cond,
    .cond = &cond,
    .extra = &extra
};

static void test_context_reset(TestContext *context)
{
    cond_reset(context->carrier->cond);
}

static TestContext test_context = {
    .carrier = &carrier_context,
    .session = NULL,
    .stream  = NULL,
    .context_reset = test_context_reset
};

static void test_add_friend(void)
{
    CarrierContext *wctxt = test_context.carrier;
    CarrierContextExtra *extra = wctxt->extra;
    char userid[IOEX_MAX_ID_LEN + 1];
    int rc;

    test_context.context_reset(&test_context);

    rc = remove_friend_anyway(&test_context, robotid);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_FALSE_FATAL(IOEX_is_friend(wctxt->carrier, robotid));

    rc = IOEX_add_friend(wctxt->carrier, robotaddr, "hello");
    CU_ASSERT_EQUAL_FATAL(rc, 0);

#if 0 // Remote robot may already be friend of test peer.
    char buf[2][32];
    rc = wait_robot_ack("%32s %32s", buf[0], buf[1]);
    CU_ASSERT_EQUAL_FATAL(rc, 2);
    CU_ASSERT_STRING_EQUAL_FATAL(buf[0], "hello");
    CU_ASSERT_STRING_EQUAL_FATAL(buf[1], "hello");
#endif

    IOEX_get_userid(wctxt->carrier, userid, sizeof(userid));
    rc = robot_ctrl("faccept %s\n", userid);
    CU_ASSERT_FATAL(rc > 0);

    // wait for friend_added() callback to be invoked.
    cond_wait(wctxt->cond);
    CU_ASSERT_TRUE(IOEX_is_friend(wctxt->carrier, robotid));
    // wait for friend connection (online) callback to be invoked.
    cond_wait(wctxt->cond);
    CU_ASSERT_TRUE(extra->connection_status == IOEXConnectionStatus_Connected);
}

static void test_accept_friend(void)
{
    CarrierContext *wctxt = test_context.carrier;
    CarrierContextExtra *extra = wctxt->extra;
    char userid[IOEX_MAX_ID_LEN + 1];
    char useraddr[IOEX_MAX_ADDRESS_LEN + 1];
    const char *hello = "hello";
    int rc;

    test_context.context_reset(&test_context);

    rc = remove_friend_anyway(&test_context, robotid);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_FALSE_FATAL(IOEX_is_friend(wctxt->carrier, robotid));

    (void)IOEX_get_userid(wctxt->carrier, userid, sizeof(userid));
    (void)IOEX_get_address(wctxt->carrier, useraddr, sizeof(useraddr));

    rc = robot_ctrl("fadd %s %s %s\n", userid, useraddr, hello);
    CU_ASSERT_FATAL(rc > 0);

    // wait for friend_request callback invoked;
    cond_wait(wctxt->cond);
    CU_ASSERT_PTR_NOT_NULL_FATAL(extra->from);
    CU_ASSERT_PTR_NOT_NULL_FATAL(extra->hello);

    CU_ASSERT_STRING_EQUAL_FATAL(extra->from, robotid);
    CU_ASSERT_STRING_EQUAL_FATAL(extra->from, extra->info.userid);
    CU_ASSERT_STRING_EQUAL_FATAL(extra->hello, hello);
    //TODO: test robot user info;

    rc = IOEX_accept_friend(wctxt->carrier, robotid);
    CU_ASSERT_EQUAL_FATAL(rc, 0);

    // wait for friend added callback invoked;
    cond_wait(wctxt->cond);
    CU_ASSERT_TRUE(IOEX_is_friend(wctxt->carrier, robotid));

    // wait for friend connection (online) callback invoked.
    cond_wait(wctxt->cond);
    CU_ASSERT_TRUE(extra->connection_status == IOEXConnectionStatus_Connected);
}

static void test_add_friend_be_friend(void)
{
    CarrierContext *wctxt = test_context.carrier;
    int rc;

    test_context.context_reset(&test_context);

    rc = add_friend_anyway(&test_context, robotid, robotaddr);
    CU_ASSERT_EQUAL_FATAL(rc, 0);
    CU_ASSERT_TRUE_FATAL(IOEX_is_friend(wctxt->carrier, robotid));

    rc = IOEX_add_friend(wctxt->carrier, robotaddr, "hello");
    CU_ASSERT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(IOEX_get_error(), IOEX_GENERAL_ERROR(IOEXERR_ALREADY_EXIST));
}

static void test_add_self_be_friend(void)
{
    CarrierContext *wctxt = test_context.carrier;
    int rc;

    char address[IOEX_MAX_ADDRESS_LEN + 1];

    (void)IOEX_get_address(wctxt->carrier, address, sizeof(address));
    rc = IOEX_add_friend(wctxt->carrier, address, "hello");

    CU_ASSERT_EQUAL(rc, -1);
    CU_ASSERT_EQUAL(IOEX_get_error(), IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
}

static CU_TestInfo cases[] = {
    { "test_add_friend",           test_add_friend           },
    { "test_accept_friend",        test_accept_friend        },
    { "test_add_friend_be_friend", test_add_friend_be_friend },
    { "test_add_self_be_friend",   test_add_self_be_friend   },
    { NULL, NULL }
};

CU_TestInfo *friend_request_test_get_cases(void)
{
    return cases;
}

int friend_request_test_suite_init(void)
{
    int rc;

    rc = test_suite_init(&test_context);
    if (rc < 0) {
        CU_FAIL("Error: test suite initialize error");
        return -1;
    }

    return 0;
}

int friend_request_test_suite_cleanup(void)
{
    test_suite_cleanup(&test_context);

    return 0;
}
