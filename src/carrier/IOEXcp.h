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

#ifndef __IOEXCPH__
#define __IOEXCPH__

#include <stdint.h>
#include <stdbool.h>
#include "IOEX_carrier.h"

typedef struct IOEXCP IOEXCP;

/* WMCP types */
#define IOEXCP_TYPE_MIN                        1

#define IOEXCP_TYPE_USERINFO                   3

#define IOEXCP_TYPE_FRIEND_REQUEST             6
#define IOEXCP_TYPE_FRIEND_REMOVE              7

#define IOEXCP_TYPE_MESSAGE                    33
#define IOEXCP_TYPE_INVITE_REQUEST             34
#define IOEXCP_TYPE_INVITE_RESPONSE            35

#define IOEXCP_TYPE_MAX                        95

IOEXCP *IOEXcp_create(uint8_t type, const char *ext_name);

void IOEXcp_free(IOEXCP *cp);

int IOEXcp_get_type(IOEXCP *cp);

const char *IOEXcp_get_extension(IOEXCP *cp);

const char *IOEXcp_get_name(IOEXCP *cp);

const char *IOEXcp_get_descr(IOEXCP *cp);

bool IOEXcp_get_has_avatar(IOEXCP *cp);

const char *IOEXcp_get_gender(IOEXCP *cp);

const char *IOEXcp_get_phone(IOEXCP *cp);

const char *IOEXcp_get_email(IOEXCP *cp);

const char *IOEXcp_get_region(IOEXCP *cp);

const char *IOEXcp_get_hello(IOEXCP *cp);

int64_t IOEXcp_get_tid(IOEXCP *cp);

int IOEXcp_get_status(IOEXCP *cp);

const void *IOEXcp_get_raw_data(IOEXCP *cp);

size_t IOEXcp_get_raw_data_length(IOEXCP *cp);

const char *IOEXcp_get_reason(IOEXCP *cp);

void IOEXcp_set_name(IOEXCP *cp, const char *name);

void IOEXcp_set_descr(IOEXCP *cp, const char *descr);

void IOEXcp_set_has_avatar(IOEXCP *cp, int has_avatar);

void IOEXcp_set_gender(IOEXCP *cp, const char *gender);

void IOEXcp_set_phone(IOEXCP *cp, const char *phone);

void IOEXcp_set_email(IOEXCP *cp, const char *email);

void IOEXcp_set_region(IOEXCP *cp, const char *region);

void IOEXcp_set_hello(IOEXCP *cp, const char *hello);

void IOEXcp_set_tid(IOEXCP *cp, int64_t *tid);

void IOEXcp_set_status(IOEXCP *cp, int status);

void IOEXcp_set_raw_data(IOEXCP *cp, const void *data, size_t len);

void IOEXcp_set_reason(IOEXCP *cp, const char *reason);

uint8_t *IOEXcp_encode(IOEXCP *cp, size_t *len);

IOEXCP *IOEXcp_decode(const uint8_t *buf, size_t len);

#endif /* __IOEXCPH__ */
