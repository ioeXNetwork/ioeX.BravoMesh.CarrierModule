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

#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>

#include <vlog.h>
#include <bitset.h>

#include "IOEXcp.h"
#include "IOEXcp_generated.h"
#include "flatcc/support/hexdump.h"
#include "IOEX_carrier.h"

#pragma pack(push, 1)

struct IOEXCP {
    uint8_t type;
    const char *ext;
};

struct IOEXCPUserInfo {
    IOEXCP header;
    bool has_avatar;
    const char *name;
    const char *descr;
    const char *phone;
    const char *gender;
    const char *email;
    const char *region;
};

struct IOEXCPFriendReq {
    IOEXCP header;
    const char *name;
    const char *descr;
    const char *hello;
};

struct IOEXCPFriendMsg {
    IOEXCP headr;
    size_t len;
    const uint8_t *msg;
};

struct IOEXCPInviteReq {
    IOEXCP header;
    int64_t tid;
    size_t len;
    const uint8_t *data;
};

struct IOEXCPInviteRsp {
    IOEXCP header;
    int64_t tid;
    int status;
    const char *reason;
    size_t len;
    const uint8_t *data;
};

#pragma pack(pop)

#define pktinfo pkt.u.pkt_info
#define pktfreq pkt.u.pkt_freq
#define pktfmsg pkt.u.pkt_fmsg
#define pktireq pkt.u.pkt_ireq
#define pktirsp pkt.u.pkt_irsp

#define tblinfo tbl.u.tbl_info
#define tblfreq tbl.u.tbl_freq
#define tblfmsg tbl.u.tbl_fmsg
#define tblireq tbl.u.tbl_ireq
#define tblirsp tbl.u.tbl_irsp

struct IOEXcp_packet_t {
    union {
        struct IOEXCP          *cp;
        struct IOEXCPUserInfo  *pkt_info;
        struct IOEXCPFriendReq *pkt_freq;
        struct IOEXCPFriendMsg *pkt_fmsg;
        struct IOEXCPInviteReq *pkt_ireq;
        struct IOEXCPInviteRsp *pkt_irsp;
    } u;
};

struct IOEXcp_table_t {
    union {
        IOEXcp_userinfo_table_t  tbl_info;
        IOEXcp_friendreq_table_t tbl_freq;
        IOEXcp_friendmsg_table_t tbl_fmsg;
        IOEXcp_invitereq_table_t tbl_ireq;
        IOEXcp_invitersp_table_t tbl_irsp;
    } u;
};

IOEXCP *IOEXcp_create(uint8_t type, const char *ext_name)
{
    IOEXCP *cp;
    size_t len;

    switch(type) {
    case IOEXCP_TYPE_USERINFO:
        len = sizeof(struct IOEXCPUserInfo);
        break;
    case IOEXCP_TYPE_FRIEND_REQUEST:
        len = sizeof(struct IOEXCPFriendReq);
        break;
    case IOEXCP_TYPE_MESSAGE:
        len = sizeof(struct IOEXCPFriendMsg);
        break;
    case IOEXCP_TYPE_INVITE_REQUEST:
        len = sizeof(struct IOEXCPInviteReq);
        break;
    case IOEXCP_TYPE_INVITE_RESPONSE:
        len = sizeof(struct IOEXCPInviteRsp);
        break;
    default:
        assert(0);
        return NULL;
    }

    cp = (IOEXCP *)calloc(1, len);
    if (!cp)
        return NULL;

    cp->type = type;
    cp->ext  = ext_name;

    return cp;
}

void IOEXcp_free(IOEXCP *cp)
{
    if (cp)
        free(cp);
}

int IOEXcp_get_type(IOEXCP *cp)
{
    assert(cp);

    return cp->type;
}

const char *IOEXcp_get_extension(IOEXCP *cp)
{
    assert(cp);

    return cp->ext;
}

const char *IOEXcp_get_name(IOEXCP *cp)
{
    struct IOEXcp_packet_t pkt;
    const char *name = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_USERINFO:
        name = pktinfo->name;
        break;
    case IOEXCP_TYPE_FRIEND_REQUEST:
        name = pktfreq->name;
        break;
    default:
        assert(0);
        break;
    }

    return name;
}

const char *IOEXcp_get_descr(IOEXCP *cp)
{
    struct IOEXcp_packet_t pkt;
    const char *descr = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_USERINFO:
        descr = pktinfo->descr;
        break;
    case IOEXCP_TYPE_FRIEND_REQUEST:
        descr = pktfreq->descr;
        break;
    default:
        assert(0);
        break;
    }

    return descr;
}

const char *IOEXcp_get_gender(IOEXCP *cp)
{
    struct IOEXcp_packet_t pkt;
    const char *gender = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_USERINFO:
        gender = pktinfo->gender;
        break;
    default:
        assert(0);
        break;
    }

    return gender;
}

const char *IOEXcp_get_phone(IOEXCP *cp)
{
    struct IOEXcp_packet_t pkt;
    const char *phone = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_USERINFO:
        phone = pktinfo->phone;
        break;
    default:
        assert(0);
        break;
    }

    return phone;
}

const char *IOEXcp_get_email(IOEXCP *cp)
{
    struct IOEXcp_packet_t pkt;
    const char *email = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_USERINFO:
        email = pktinfo->email;
        break;
    default:
        assert(0);
        break;
    }

    return email;
}

const char *IOEXcp_get_region(IOEXCP *cp)
{
    struct IOEXcp_packet_t pkt;
    const char *region = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_USERINFO:
        region = pktinfo->region;
        break;
    default:
        assert(0);
        break;
    }

    return region;
}

bool IOEXcp_get_has_avatar(IOEXCP *cp)
{
    struct IOEXcp_packet_t pkt;
    bool has_avatar = 0;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_USERINFO:
        has_avatar = pktinfo->has_avatar;
        break;
    default:
        assert(0);
        break;
    }

    return has_avatar;
}

const char *IOEXcp_get_hello(IOEXCP *cp)
{
    struct IOEXcp_packet_t pkt;
    const char *hello = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_FRIEND_REQUEST:
        hello = pktfreq->hello;
        break;
    default:
        assert(0);
        break;
    }

    return hello;
}

int64_t IOEXcp_get_tid(IOEXCP *cp)
{
    struct IOEXcp_packet_t pkt;
    int64_t tid = 0;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_INVITE_REQUEST:
        tid = pktireq->tid;
        break;
    case IOEXCP_TYPE_INVITE_RESPONSE:
        tid = pktirsp->tid;
        break;
    default:
        assert(0);
        break;
    }

    return tid;
}

int IOEXcp_get_status(IOEXCP *cp)
{
    struct IOEXcp_packet_t pkt;
    int status = 0;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_INVITE_RESPONSE:
        status = pktirsp->status;
        break;
    default:
        assert(0);
        break;
    }

    return status;
}

const void *IOEXcp_get_raw_data(IOEXCP *cp)
{
    struct IOEXcp_packet_t pkt;
    const void *data = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_MESSAGE:
        data = pktfmsg->msg;
        break;
    case IOEXCP_TYPE_INVITE_REQUEST:
        data = pktireq->data;
        break;
    case IOEXCP_TYPE_INVITE_RESPONSE:
        data = pktirsp->data;
        break;
    default:
        assert(0);
        break;
    }

    return data;
}

size_t IOEXcp_get_raw_data_length(IOEXCP *cp)
{
    struct IOEXcp_packet_t pkt;
    size_t len = 0;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_MESSAGE:
        len = pktfmsg->len;
        break;
    case IOEXCP_TYPE_INVITE_REQUEST:
        len = pktireq->len;
        break;
    case IOEXCP_TYPE_INVITE_RESPONSE:
        len = pktirsp->len;
        break;
    default:
        assert(0);
        break;
    }

    return len;
}

const char *IOEXcp_get_reason(IOEXCP *cp)
{
    struct IOEXcp_packet_t pkt;
    const char *reason = NULL;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_INVITE_RESPONSE:
        reason = pktirsp->reason;
        break;
    default:
        assert(0);
        break;
    }

    return reason;
}

void IOEXcp_set_name(IOEXCP *cp, const char *name)
{
    struct IOEXcp_packet_t pkt;

    assert(cp);
    assert(name);

    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_USERINFO:
        pktinfo->name = name;
        break;
    case IOEXCP_TYPE_FRIEND_REQUEST:
        pktfreq->name = name;
        break;
    default:
        assert(0);
        break;
    }
}

void IOEXcp_set_descr(IOEXCP *cp, const char *descr)
{
    struct IOEXcp_packet_t pkt;

    assert(cp);
    assert(descr);

    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_USERINFO:
        pktinfo->descr = descr;
        break;
    case IOEXCP_TYPE_FRIEND_REQUEST:
        pktfreq->descr = descr;
        break;
    default:
        assert(0);
        break;
    }
}

void IOEXcp_set_gender(IOEXCP *cp, const char *gender)
{
    struct IOEXcp_packet_t pkt;

    assert(cp);
    assert(gender);

    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_USERINFO:
        pktinfo->gender = gender;
        break;
    default:
        assert(0);
        break;
    }
}

void IOEXcp_set_phone(IOEXCP *cp, const char *phone)
{
    struct IOEXcp_packet_t pkt;

    assert(cp);
    assert(phone);

    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_USERINFO:
        pktinfo->phone = phone;
        break;
    default:
        assert(0);
        break;
    }
}

void IOEXcp_set_email(IOEXCP *cp, const char *email)
{
    struct IOEXcp_packet_t pkt;

    assert(cp);
    assert(email);

    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_USERINFO:
        pktinfo->email = email;
        break;
    default:
        assert(0);
        break;
    }
}

void IOEXcp_set_region(IOEXCP *cp, const char *region)
{
    struct IOEXcp_packet_t pkt;

    assert(cp);
    assert(region);

    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_USERINFO:
        pktinfo->region = region;
        break;
    default:
        assert(0);
        break;
    }
}

void IOEXcp_set_has_avatar(IOEXCP *cp, int has_avatar)
{
    struct IOEXcp_packet_t pkt;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_USERINFO:
        pktinfo->has_avatar = !!has_avatar;
        break;
    default:
        assert(0);
        break;
    }
}

void IOEXcp_set_hello(IOEXCP *cp, const char *hello)
{
    struct IOEXcp_packet_t pkt;

    assert(cp);
    assert(hello);

    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_FRIEND_REQUEST:
        pktfreq->hello = hello;
        break;
    default:
        assert(0);
        break;
    }
}

void IOEXcp_set_tid(IOEXCP *cp, int64_t *tid)
{
    struct IOEXcp_packet_t pkt;

    assert(cp);
    assert(tid);

    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_INVITE_REQUEST:
        pktireq->tid = *tid;
        break;
    case IOEXCP_TYPE_INVITE_RESPONSE:
        pktirsp->tid = *tid;
        break;
    default:
        assert(0);
        break;
    }
}

void IOEXcp_set_status(IOEXCP *cp, int status)
{
    struct IOEXcp_packet_t pkt;

    assert(cp);
    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_INVITE_RESPONSE:
        pktirsp->status = status;
        break;
    default:
        assert(0);
        break;
    }
}

void IOEXcp_set_raw_data(IOEXCP *cp, const void *data, size_t len)
{
    struct IOEXcp_packet_t pkt;

    assert(cp);
    assert(data);
    assert(len > 0);

    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_MESSAGE:
        pktfmsg->msg = data;
        pktfmsg->len = len;
        break;
    case IOEXCP_TYPE_INVITE_REQUEST:
        pktireq->data = data;
        pktireq->len = len;
        break;
    case IOEXCP_TYPE_INVITE_RESPONSE:
        pktirsp->data = data;
        pktirsp->len = len;
        break;
    default:
        assert(0);
        break;
    }
}

void IOEXcp_set_reason(IOEXCP *cp, const char *reason)
{
    struct IOEXcp_packet_t pkt;

    assert(cp);
    assert(reason);

    pkt.u.cp = cp;

    switch(cp->type) {
    case IOEXCP_TYPE_INVITE_RESPONSE:
        pktirsp->reason = reason;
        break;
    default:
        assert(0);
        break;
    }
}

uint8_t *IOEXcp_encode(IOEXCP *cp, size_t *encoded_len)
{
    struct IOEXcp_packet_t pkt;
    flatcc_builder_t builder;
    flatcc_builder_ref_t str;
    flatbuffers_uint8_vec_ref_t vec;
    flatbuffers_ref_t ref;
    IOEXcp_anybody_union_ref_t body;
    uint8_t *encoded_data;

    assert(cp);
    assert(encoded_len);

    pkt.u.cp = cp;

    flatcc_builder_init(&builder);

    switch(cp->type) {
    case IOEXCP_TYPE_USERINFO:
        IOEXcp_userinfo_start(&builder);
        if (pktinfo->name) {
            str = flatcc_builder_create_string_str(&builder, pktinfo->name);
            IOEXcp_userinfo_name_add(&builder, str);
        }
        str = flatcc_builder_create_string_str(&builder, pktinfo->descr);
        IOEXcp_userinfo_descr_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktinfo->gender);
        IOEXcp_userinfo_gender_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktinfo->phone);
        IOEXcp_userinfo_phone_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktinfo->email);
        IOEXcp_userinfo_email_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktinfo->region);
        IOEXcp_userinfo_region_add(&builder, str);
        IOEXcp_userinfo_avatar_add(&builder, pktinfo->has_avatar);
        ref = IOEXcp_userinfo_end(&builder);
        break;

    case IOEXCP_TYPE_FRIEND_REQUEST:
        IOEXcp_friendreq_start(&builder);
        str = flatcc_builder_create_string_str(&builder, pktfreq->name);
        IOEXcp_friendreq_name_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktfreq->descr);
        IOEXcp_friendreq_descr_add(&builder, str);
        str = flatcc_builder_create_string_str(&builder, pktfreq->hello);
        IOEXcp_friendreq_hello_add(&builder, str);
        ref = IOEXcp_friendreq_end(&builder);
        break;

    case IOEXCP_TYPE_MESSAGE:
        IOEXcp_friendmsg_start(&builder);
        if (cp->ext) {
            str = flatcc_builder_create_string_str(&builder, cp->ext);
            IOEXcp_friendmsg_ext_add(&builder, str);
        }

        vec = flatbuffers_uint8_vec_create(&builder, pktfmsg->msg, pktfmsg->len);
        IOEXcp_friendmsg_msg_add(&builder, vec);
        ref = IOEXcp_friendmsg_end(&builder);
        break;

    case IOEXCP_TYPE_INVITE_REQUEST:
        IOEXcp_invitereq_start(&builder);
        if (cp->ext) {
            str = flatcc_builder_create_string_str(&builder, cp->ext);
            IOEXcp_friendmsg_ext_add(&builder, str);
        }
        IOEXcp_invitereq_tid_add(&builder, pktireq->tid);
        vec = flatbuffers_uint8_vec_create(&builder, pktireq->data, pktireq->len);
        IOEXcp_invitereq_data_add(&builder, vec);
        ref = IOEXcp_invitereq_end(&builder);
        break;

    case IOEXCP_TYPE_INVITE_RESPONSE:
        IOEXcp_invitersp_start(&builder);
        if (cp->ext) {
            str = flatcc_builder_create_string_str(&builder, cp->ext);
            IOEXcp_friendmsg_ext_add(&builder, str);
        }
        IOEXcp_invitersp_tid_add(&builder, pktirsp->tid);
        IOEXcp_invitersp_status_add(&builder, pktirsp->status);
        if (pktirsp->status) {
            str = flatcc_builder_create_string_str(&builder, pktirsp->reason);
            IOEXcp_invitersp_reason_add(&builder, str);
        } else {
            vec = flatbuffers_uint8_vec_create(&builder, pktirsp->data, pktirsp->len);
            IOEXcp_invitersp_data_add(&builder, vec);
        }
        ref = IOEXcp_invitersp_end(&builder);
        break;

    default:
        assert(0);
        ref = 0; // to clean builder.
        break;
    }

    if (!ref) {
        flatcc_builder_clear(&builder);
        return NULL;
    }

    switch(cp->type) {
    case IOEXCP_TYPE_USERINFO:
        body = IOEXcp_anybody_as_userinfo(ref);
        break;
    case IOEXCP_TYPE_FRIEND_REQUEST:
        body = IOEXcp_anybody_as_friendreq(ref);
        break;
    case IOEXCP_TYPE_MESSAGE:
        body = IOEXcp_anybody_as_friendmsg(ref);
        break;
    case IOEXCP_TYPE_INVITE_REQUEST:
        body = IOEXcp_anybody_as_invitereq(ref);
        break;
    case IOEXCP_TYPE_INVITE_RESPONSE:
        body = IOEXcp_anybody_as_invitersp(ref);
        break;
    default:
        assert(0);
        return NULL;
    }

    IOEXcp_packet_start_as_root(&builder);
    IOEXcp_packet_type_add(&builder, cp->type);
    IOEXcp_packet_body_add(&builder, body);
    if (!IOEXcp_packet_end_as_root(&builder)) {
        flatcc_builder_clear(&builder);
        return NULL;
    }

    encoded_data = flatcc_builder_finalize_buffer(&builder, encoded_len);
    flatcc_builder_clear(&builder);

    return encoded_data;
}

IOEXCP *IOEXcp_decode(const uint8_t *data, size_t len)
{
    IOEXCP *cp;
    struct IOEXcp_packet_t pkt;
    struct IOEXcp_table_t  tbl;
    IOEXcp_packet_table_t packet;
    flatbuffers_uint8_vec_t vec;
    uint8_t type;

    packet = IOEXcp_packet_as_root(data);
    if (!packet)
        return NULL;

    type = IOEXcp_packet_type(packet);
    switch(type) {
    case IOEXCP_TYPE_USERINFO:
    case IOEXCP_TYPE_FRIEND_REQUEST:
    case IOEXCP_TYPE_MESSAGE:
    case IOEXCP_TYPE_INVITE_REQUEST:
    case IOEXCP_TYPE_INVITE_RESPONSE:
        break;
    default:
        //TODO: clean resource for 'packet'; (how ?)
        return NULL;
    }

    cp = IOEXcp_create(type, NULL);
    if (!cp) {
        //TODO: clean resource for 'packet'; (how ?)
        return NULL;
    }
    pkt.u.cp = cp;

    if (!IOEXcp_packet_body_is_present(packet)) {
        IOEXcp_free(cp);
        return NULL;
    }

    switch(type) {
    case IOEXCP_TYPE_USERINFO:
        tblinfo = IOEXcp_packet_body(packet);
        if (IOEXcp_userinfo_name_is_present(tblinfo))
            pktinfo->name = IOEXcp_userinfo_name(tblinfo);
        pktinfo->descr  = IOEXcp_userinfo_descr(tblinfo);
        pktinfo->gender = IOEXcp_userinfo_gender(tblinfo);
        pktinfo->phone  = IOEXcp_userinfo_phone(tblinfo);
        pktinfo->email  = IOEXcp_userinfo_email(tblinfo);
        pktinfo->region = IOEXcp_userinfo_region(tblinfo);
        pktinfo->has_avatar = IOEXcp_userinfo_avatar(tblinfo);
        break;

    case IOEXCP_TYPE_FRIEND_REQUEST:
        tblfreq = IOEXcp_packet_body(packet);
        pktfreq->name  = IOEXcp_friendreq_name(tblfreq);
        pktfreq->descr = IOEXcp_friendreq_descr(tblfreq);
        pktfreq->hello = IOEXcp_friendreq_hello(tblfreq);
        break;

    case IOEXCP_TYPE_MESSAGE:
        tblfmsg = IOEXcp_packet_body(packet);
        pktfmsg->msg = vec = IOEXcp_friendmsg_msg(tblfmsg);
        pktfmsg->len = flatbuffers_uint8_vec_len(vec);
        if (IOEXcp_friendmsg_ext_is_present(tblfmsg))
            cp->ext = IOEXcp_friendmsg_ext(tblfmsg);
        break;

    case IOEXCP_TYPE_INVITE_REQUEST:
        tblireq = IOEXcp_packet_body(packet);
        pktireq->tid = IOEXcp_invitereq_tid(tblireq);
        pktireq->data = vec = IOEXcp_invitereq_data(tblireq);
        pktireq->len = flatbuffers_uint8_vec_len(vec);
        if (IOEXcp_invitereq_ext_is_present(tblireq))
            cp->ext = IOEXcp_invitereq_ext(tblireq);
        break;

    case IOEXCP_TYPE_INVITE_RESPONSE:
        tblirsp = IOEXcp_packet_body(packet);
        pktirsp->tid = IOEXcp_invitersp_tid(tblirsp);
        pktirsp->status = IOEXcp_invitersp_status(tblirsp);
        if (pktirsp->status)
            pktirsp->reason = IOEXcp_invitersp_reason(tblirsp);
        else {
            pktirsp->data = vec = IOEXcp_invitersp_data(tblirsp);
            pktirsp->len = flatbuffers_uint8_vec_len(vec);
        }
        if (IOEXcp_invitersp_ext_is_present(tblirsp))
            cp->ext = IOEXcp_invitersp_ext(tblirsp);
        break;

    default:
        assert(0);
        break;
    }

    return cp;
}
