/*
 * Copyright (c) 2018 Elastos Foundation
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
/*
 * Copyright (c) 2018 ioeXNetwork
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
 

#ifndef __TEST_HELPER_H__
#define __TEST_HELPER_H__

#include "IOEX_carrier.h"
#include "IOEX_session.h"

typedef struct Condition Condition;
typedef struct CarrierContextExtra CarrierContextExtra;
typedef struct SessionContextExtra SessionContextExtra;
typedef struct StreamContextExtra  StreamContextExtra;

typedef struct StreamContext {
    IOEXStreamCallbacks *cbs;
    int stream_id;
    IOEXStreamState state;
    uint8_t state_bits;
    Condition *cond;

    StreamContextExtra *extra;
} StreamContext;

typedef struct SessionContext {
    IOEXSessionRequestCallback *request_cb;
    int request_received;
    Condition *request_cond;

    IOEXSessionRequestCompleteCallback *request_complete_cb;
    int request_complete_status;
    Condition *request_complete_cond;

    IOEXSession *session;

    SessionContextExtra *extra;
} SessionContext;

typedef struct CarrierContext {
    IOEXCallbacks *cbs;
    IOEXCarrier *carrier;
    Condition *ready_cond;
    Condition *cond;
    pthread_t thread;
    volatile bool robot_online;

    CarrierContextExtra *extra;
} CarrierContext;

typedef struct TestContext TestContext;

struct TestContext {
    CarrierContext *carrier;
    SessionContext *session;
    StreamContext  *stream;

    void (*context_reset)(TestContext *);
};

#define FREE_ANYWAY(ptr) do {   \
    if ((ptr)) {                \
        free(ptr);              \
        (ptr) = NULL;           \
    }                           \
} while(0)

int test_suite_init_ext(TestContext *ctx, bool udp_disabled);

int test_suite_init(TestContext *ctx);

int test_suite_cleanup(TestContext *ctx);

int add_friend_anyway(TestContext *ctx, const char *userid, const char *address);

int remove_friend_anyway(TestContext *ctx, const char *userid);

int robot_sinit(void);

void robot_sfree(void);

const char *stream_state_name(IOEXStreamState state);

void test_stream_scheme(IOEXStreamType stream_type, int stream_options,
                        TestContext *context, int (*do_work_cb)(TestContext *));

const char* connection_str(enum IOEXConnectionStatus status);

#endif /* __TEST_HELPER_H__ */
