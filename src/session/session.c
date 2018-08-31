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
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>

#include <rc_mem.h>
#include <time_util.h>
#include <linkedlist.h>
#include <vlog.h>

#include "IOEX_session.h"
#include "IOEX_turnserver.h"
#include "portforwarding.h"
#include "services.h"
#include "session.h"
#include "socket.h"
#include "stream_handler.h"
#include "multiplex_handler.h"
#include "flex_buffer.h"
#include "ice.h"

#define SDP_MAX_LEN                 2048
static const char *extension_name = "session";

#if defined(__ANDROID__)
extern int PJ_JNI_OnLoad(void *vm, void* reserved);

bool IOEX_session_jni_onload(void *vm, void *reserved)
{
    int rc;

    rc = PJ_JNI_OnLoad(vm, reserved);
    return (rc >= 0);
}
#endif

static void friend_invite(IOEXCarrier *w, const char *from, const char *sdp,
                          size_t len, void *context)
{
    SessionExtension *ext;

    ext = (SessionExtension *)context;
    if (!ext) {
        vlogE("Session: Internal error!");
        return;
    }

    vlogD("Session: Session request from %s with SDP %.*s", from, (int)len, sdp);

    if (ext->request_callback)
        ext->request_callback(w, from, sdp, len, ext->context);
}

static void remove_transport(IOEXTransport *);

static void extension_destroy(void *p)
{
    SessionExtension *ext = (SessionExtension *)p;

    if (ext->transport)
        remove_transport(ext->transport);

    ids_heap_destroy((IdsHeap *)&ext->stream_ids);

    vlogD("Session: Extension destroyed.");
}

static int add_transport(SessionExtension *ext)
{
    IOEXTransport *transport;
    int rc;

    assert(ext);

    if (ext->transport)
        return IOEX_GENERAL_ERROR(IOEXERR_ALREADY_EXIST);

    rc = ext->create_transport(&transport);
    if (rc < 0)
        return rc;

    transport->workers = list_create(1, NULL);
    if (!transport->workers) {
        deref(transport);
        return IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY);
    }

    transport->ext = ext;
    ext->transport = transport;

    return 0;
}

int IOEX_session_init(IOEXCarrier *w, IOEXSessionRequestCallback *callback, void *context)
{
    SessionExtension *ext;
    int rc;

    if (!w) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (w->extension) {
        vlogD("Session: Session already initialized");
        return 0;
    }

    ext = (SessionExtension *)rc_zalloc(sizeof(SessionExtension),
                                           extension_destroy);
    if (!ext) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return -1;
    }

    ext->carrier = w;
    ext->friend_invite_cb = friend_invite;
    ext->friend_invite_context = ext;

    ext->request_callback = callback;
    ext->context = context;
    ext->create_transport = ice_transport_create;

    rc = ids_heap_init((IdsHeap *)&ext->stream_ids, MAX_STREAM_ID);
    if (rc < 0) {
        deref(ext);
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return -1;
    }

    rc = add_transport(ext);
    if (rc < 0) {
        deref(ext);
        IOEX_set_error(rc);
        return -1;
    }

    w->extension = ext;

    vlogD("Session: Initialize session extension %s.",
          rc == 0 ? "success" : "failed");

    return rc;
}

static void remove_transport(IOEXTransport *transport)
{
    ListIterator it;

    if (!transport)
        return;

restop_workers:
    list_iterate(transport->workers, &it);
    while(list_iterator_has_next(&it)) {
        TransportWorker *wk;
        int rc;

        rc = list_iterator_next(&it, (void **)&wk);
        if (rc == 0)
            break;

        if (rc == -1)
            goto restop_workers;

        wk->stop(wk);
        deref(wk);

        // Hold the zombie worker object and clear on transport destroy.
    }

    deref(transport);
}

void IOEX_session_cleanup(IOEXCarrier *w)
{
    SessionExtension *ext;

    if (!w || !w->extension)
         return;

    ext = w->extension;
    w->extension = NULL;

    if (ext->transport) {
        remove_transport(ext->transport);
        ext->transport = NULL;
    }

    deref(ext);

    vlogD("Session: Extension cleanuped.");
}

void transport_base_destroy(void *p)
{
    IOEXTransport *transport = (IOEXTransport *)p;

    if (transport->workers)
        deref(transport->workers);

    vlogD("Session: ICE transport destroyed.");
}

void session_base_destroy(void *p)
{
    IOEXSession *ws = (IOEXSession *)p;

    if (ws->streams)
        deref(ws->streams);

    if (ws->portforwarding.services)
        deref(ws->portforwarding.services);

    if (ws->worker)
        deref(ws->worker);

    vlogD("Session: Session to %s destroyed.", ws->to);

    if (ws->to)
        free(ws->to);
}

IOEXSession *IOEX_session_new(IOEXCarrier *w, const char *address)
{
    SessionExtension *ext;
    IOEXSession *ws;
    IOEXTransport *transport;
    IceTransportOptions opts;
    IOEXTurnServer turn_server;
    int rc;

    if (!w || !address) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return NULL;
    }

    ext = w->extension;
    if (!ext) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return NULL;
    }

    if (!IOEX_is_friend(w, address)) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        vlogE("Session: %s is not friend yet.", address);
        return NULL;
    }

    transport = ext->transport;
    if (!transport) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        vlogE("Session: Transport not intialized yet.");
        return NULL;
    }

    rc = transport->create_session(transport, &ws);
    if (rc != 0) {
        IOEX_set_error(rc);
        return NULL;
    }

    ws->streams = list_create(1, NULL);
    if (!ws->streams) {
        deref(ws);
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return NULL;
    }

    ws->transport = transport;
    ws->to = strdup(address);

    rc = IOEX_get_turn_server(w, &turn_server);
    if (rc < 0) {
        deref(ws);
        return NULL;
    }

    opts.stun_host = turn_server.server;
    opts.stun_port = NULL;
    opts.turn_host = turn_server.server;
    opts.turn_port = NULL;
    opts.turn_username = turn_server.username;
    opts.turn_password = turn_server.password;
    opts.turn_realm = turn_server.realm;

    rc = transport->create_worker(transport, &opts, &ws->worker);
    if (rc < 0) {
        deref(ws);
        IOEX_set_error(rc);
        return NULL;
    }
    ws->worker->le.data = ws->worker;

    rc = ws->init(ws);
    if (rc < 0) {
        deref(ws);
        IOEX_set_error(rc);
        return NULL;
    }

    list_add(transport->workers, &ws->worker->le);

    vlogD("Session: Session to %s created.", ws->to);

    return ws;
}

char *IOEX_session_get_peer(IOEXSession *ws, char *peer, size_t size)
{
    if (!ws || !peer || !size) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return NULL;
    }

    if (size <= strlen(ws->to)) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_BUFFER_TOO_SMALL));
        return NULL;
    }

    strcpy(peer, ws->to);
    return peer;
}

void IOEX_session_set_userdata(IOEXSession *ws, void *userdata)
{
    if (ws)
        ws->userdata = userdata;
}

void *IOEX_session_get_userdata(IOEXSession *ws)
{
    return ws ? ws->userdata : NULL;
}

static void session_internal_close(IOEXSession *ws)
{
    ListIterator it;
    assert(ws);

restop:
    list_iterate(ws->streams, &it);
    while (list_iterator_has_next(&it)) {
        IOEXStream *s;
        int rc;

        rc = list_iterator_next(&it, (void **)&s);
        if (rc == 0)
            break;

        if (rc == -1)
            goto restop;

        s->pipeline.stop(&s->pipeline, 0);
        deref(s);

        //Hold the zombie stream object, clear on session destroy.
    }

    if (ws->worker) {
        deref(list_remove_entry(ws->transport->workers, &ws->worker->le));
        ws->worker->stop(ws->worker);
    }

    // Clear sensitive data for security reason
    memset(ws->secret_key, 0, sizeof(ws->secret_key));
    memset(ws->credential, 0, sizeof(ws->credential));
    memset(ws->nonce, 0, sizeof(ws->nonce));
    memset(ws->crypto.key, 0, sizeof(ws->crypto.key));
}

void IOEX_session_close(IOEXSession *ws)
{
    if (ws) {
        vlogD("Session: Closing session to %s.", ws->to);

        session_internal_close(ws);

        vlogD("Session: Session to %s closed.", ws->to);
        deref(ws);
   }
}

static void friend_invite_response(IOEXCarrier *w, const char *from,
                                   int status, const char *reason,
                                   const void *sdp, size_t len, void *context)
{
    IOEXSession *ws = (IOEXSession*)context;

    if (ws->complete_callback) {
        ws->complete_callback(ws, status, reason, (const char *)sdp, len, ws->context);
    }
}

int IOEX_session_request(IOEXSession *ws,
        IOEXSessionRequestCompleteCallback *callback, void *context)
{
    IOEXCarrier *w;
    int rc = 0;
    ListIterator iterator;
    char sdp[SDP_MAX_LEN];
    char *ext_to;

    if (!ws || !callback) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    w = session_get_extension(ws)->carrier;
    assert(w);

    if (list_size(ws->streams) == 0) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE));
        return -1;
    }

    ws->offerer = 1;
    if (!ws->set_offer(ws, true)) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE));
        return -1;
    }

    crypto_create_keypair(ws->public_key, ws->secret_key);
    crypto_random_nonce(ws->nonce);
    crypto_random_nonce(ws->credential);

reprepare:
    list_iterate(ws->streams, &iterator);
    while (list_iterator_has_next(&iterator)) {
        IOEXStream *s;

        rc = list_iterator_next(&iterator, (void **)&s);
        if (rc == 0)
            break;

        if (rc == -1)
            goto reprepare;

        rc = s->pipeline.prepare(&s->pipeline);
        deref(s);

        if (rc != 0) {
            IOEX_set_error(rc);
            return -1;
        }
    }

    rc = ws->encode_local_sdp(ws, sdp, sizeof(sdp));
    if (rc < 0) {
        vlogE("Session: Encode local SDP failed(0x%x).", rc);
        IOEX_set_error(rc);
        return -1;
    }
    // IMPORTANT: add terminal null
    sdp[rc] = 0;

    vlogD("Session: Encode local SDP success[%s].", sdp);

    ws->complete_callback = callback;
    ws->context = context;

    ext_to = (char *)alloca(IOEX_MAX_ID_LEN + strlen(extension_name) + 2);
    strcpy(ext_to, ws->to);
    strcat(ext_to, ":");
    strcat(ext_to, extension_name);

    rc = IOEX_invite_friend(w, ext_to, sdp, rc + 1,
                           friend_invite_response, (void *)ws);

    vlogD("Session: Session request to %s %s.", ws->to,
          rc == 0 ? "success" : "failed");

    return rc;
}

int IOEX_session_reply_request(IOEXSession *ws,
                              int status, const char* reason)
{
    IOEXCarrier *w;
    int rc = 0;
    char sdp[SDP_MAX_LEN];
    char *local_sdp = NULL;
    size_t sdp_len = 0;
    char *ext_to;

    if (!ws || (status != 0 && !reason)) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    w = session_get_extension(ws)->carrier;
    assert(w);

    ws->offerer = 0;
    if (!ws->set_offer(ws, false)) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE));
        return -1;
    }

    crypto_create_keypair(ws->public_key, ws->secret_key);
    crypto_random_nonce(ws->nonce);
    crypto_random_nonce(ws->credential);

    if (status == 0) {
        ListIterator iterator;

        if (list_size(ws->streams) == 0) {
            IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE));
            return -1;
        }

reprepare:
        list_iterate(ws->streams, &iterator);
        while (list_iterator_has_next(&iterator)) {
            IOEXStream *s;

            rc = list_iterator_next(&iterator, (void **)&s);
            if (rc == 0)
                break;

            if (rc == -1)
                goto reprepare;

            rc = s->pipeline.prepare(&s->pipeline);
            deref(s);

            if (rc != 0) {
                IOEX_set_error(rc);
                return -1;
            }
        }

        rc = ws->encode_local_sdp(ws, sdp, sizeof(sdp));
        if (rc < 0) {
            vlogE("Session: Encode local SDP failed(0x%x).", rc);
            IOEX_set_error(rc);
            return -1;
        }
        // IMPORTANT: add terminal null
        sdp[rc] = 0;

        vlogD("Session: Encode local SDP success[%s].", sdp);

        local_sdp = sdp;
        sdp_len = rc + 1;
    }

    ext_to = (char *)alloca(IOEX_MAX_ID_LEN + strlen(extension_name) + 2);
    strcpy(ext_to, ws->to);
    strcat(ext_to, ":");
    strcat(ext_to, extension_name);

    rc = IOEX_reply_friend_invite(w, ext_to, status, reason,
                                 local_sdp, sdp_len);

    vlogD("Session: Session reply to %s %s.", ws->to,
          rc == 0 ? "success" : "failed");

    return rc;
}

int IOEX_session_start(IOEXSession *ws, const char *sdp, size_t len)
{
    int rc;
    ListIterator iterator;

    if (!ws || !sdp || !len) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (list_size(ws->streams) == 0) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE));
        return -1;
    }

    if (ws->crypto.enabled)
        crypto_compute_symmetric_key(ws->peer_pubkey, ws->secret_key,
                                     ws->crypto.key);

    ref(ws);

recheck:
    list_iterate(ws->streams, &iterator);
    while (list_iterator_has_next(&iterator)) {
        IOEXStream *s;
        bool ready;

        rc = list_iterator_next(&iterator, (void **)&s);
        if (rc == 0)
            break;

        if (rc == -1)
            goto recheck;

        ready = (s->state == IOEXStreamState_transport_ready);
        deref(s);

        if (!ready) {
            deref(ws);
            IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE));
            return -1;
        }
    }

    rc = ws->apply_remote_sdp(ws, (char *)sdp, len-1);
    if (rc < 0) {
        vlogE("Session: Session to %s can not apply remote SDP.)", ws->to);
        vlogT("Session: Wrong SDP is: [%.*s].", (int)(len - 1), sdp);
        deref(ws);
        IOEX_set_error(rc);
        return -1;
    }

restart:
    list_iterate(ws->streams, &iterator);
    while (list_iterator_has_next(&iterator)) {
        IOEXStream *s;

        rc = list_iterator_next(&iterator, (void **)&s);
        if (rc == 0)
            break;

        if (rc == -1)
            goto restart;

        if (!s->deactivate)
            s->pipeline.start(&s->pipeline);
        else
            s->fire_state_changed(s, IOEXStreamState_deactivated);

        deref(s);
    }

    deref(ws);

    return 0;
}

void stream_base_destroy(void *p)
{
    IOEXStream *s = (IOEXStream *)p;

    if (s->pipeline.next)
        deref(s->pipeline.next);

    if (s->id > 0)
        ids_heap_free((IdsHeap *)&stream_get_extension(s)->stream_ids, s->id);

    vlogD("Session: Stream %d destroyed", s->id);
}

static
void stream_base_on_data(StreamHandler *handler, FlexBuffer *buf)
{
    IOEXStream *s = (IOEXStream *)handler;

    if (s->callbacks.stream_data)
        s->callbacks.stream_data(s->session, s->id,
                                 flex_buffer_ptr(buf), flex_buffer_size(buf),
                                 s->context);
}

static
void stream_base_on_state_chagned(StreamHandler *handler, int state)
{
    IOEXStream *s = (IOEXStream *)handler;

    s->state = state;

    if (s->callbacks.state_changed)
        s->callbacks.state_changed(s->session, s->id, state, s->context);
}

int IOEX_session_add_stream(IOEXSession *ws, IOEXStreamType type,
                           int options,
                           IOEXStreamCallbacks *callbacks, void *context)
{
    IOEXStream *s;
    StreamHandler *prev;
    StreamHandler *handler;
    int rc;

    if (!ws) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (type == IOEXStreamType_audio || type == IOEXStreamType_video) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_IMPLEMENTED));
        return -1;
    }

    rc = ws->create_stream(ws, &s);
    if (rc != 0) {
        IOEX_set_error(rc);
        return -1;
    }

    s->session = ws;

    s->id = ids_heap_alloc((IdsHeap *)&session_get_extension(ws)->stream_ids);
    if (s->id <= 0) {
        vlogE("Session: Too many streams!");
        deref(s);
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return -1;
    }

    s->type = type;
    s->state = 0;
    if (callbacks) {
        s->callbacks = *callbacks;
        s->context = context;
    }

    if (options & IOEX_STREAM_COMPRESS)
        s->compress = 1;
    if (options & IOEX_STREAM_PLAIN)
        s->unencrypt = 1;
    if (options & IOEX_STREAM_RELIABLE)
        s->reliable = 1;
    if (options & IOEX_STREAM_MULTIPLEXING)
        s->multiplexing = 1;
    if (options & IOEX_STREAM_PORT_FORWARDING) {
        s->multiplexing = 1;
        s->portforwarding = 1;
    }

    s->pipeline.name = "Root Handler";
    s->pipeline.init = default_handler_init;
    s->pipeline.prepare = default_handler_prepare;
    s->pipeline.start = default_handler_start;
    s->pipeline.stop = default_handler_stop;
    s->pipeline.write = default_handler_write;
    s->pipeline.on_data = stream_base_on_data;
    s->pipeline.on_state_changed = stream_base_on_state_chagned;

    prev = &s->pipeline;

    if (s->multiplexing) {
        MultiplexHandler *handler;

        rc = multiplex_handler_create(s, &handler);
        if (rc < 0) {
            deref(s);
            IOEX_set_error(rc);
            return -1;
        }

        s->mux = &handler->mux;
        handler_connect(prev, &handler->base);
        prev = &handler->base;
    }

    if (s->reliable) {
        rc = reliable_handler_create(s, &handler);
        if (rc < 0) {
            deref(s);
            IOEX_set_error(rc);
            return -1;
        }
        handler_connect(prev, handler);
        prev = handler;
    }

    if (!s->unencrypt) {
        s->session->crypto.enabled = 1;
        rc = crypto_handler_create(s, &handler);
        if (rc < 0) {
            deref(s);
            IOEX_set_error(rc);
            return -1;
        }
        handler_connect(prev, handler);
        prev = handler;
    }

    s->le.data = s;
    list_add(ws->streams, &s->le);

    rc = s->pipeline.init(&s->pipeline);
    if (rc < 0) {
        deref(list_remove_entry(ws->streams, &s->le));
        deref(s);
        IOEX_set_error(rc);
        return -1;
    }

    deref(s);

    vlogD("Session: Create stream %d", s->id);

    return s->id;
}

static IOEXStream *get_stream(IOEXSession *ws, int stream)
{
    IOEXStream *s;
    ListIterator iterator;
    int rc;

    assert(ws);
    assert(stream > 0);

rescan:
    list_iterate(ws->streams, &iterator);
    while (list_iterator_has_next(&iterator)) {
        rc = list_iterator_next(&iterator, (void **)&s);
        if (rc == 0)
            break;

        if (rc == -1)
            goto rescan;

        if (s->id == stream)
            return s;

        deref(s);
    }

    return NULL;
}

int IOEX_session_remove_stream(IOEXSession *ws, int stream)
{
    IOEXStream *s;

    if (!ws || stream <= 0) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    s = get_stream(ws, stream);
    if (!s) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    s->pipeline.stop(&s->pipeline, 0);

    deref(list_remove_entry(ws->streams, &s->le));

    vlogD("Session: Remove stream %d.", s->id);

    deref(s);

    return 0;
}

ssize_t IOEX_stream_write(IOEXSession *ws, int stream,
                         const void *data, size_t len)
{
    IOEXStream *s;
    FlexBuffer *buf;
    ssize_t sent;

    if (!ws || stream <= 0 || !data || !len || len > IOEX_MAX_USER_DATA_LEN) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    s = get_stream(ws, stream);
    if (!s) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    if (s->type == IOEXStreamType_audio || s->type == IOEXStreamType_video) {
        deref(s);
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_IMPLEMENTED));
        return -1;
    }

    if (s->state != IOEXStreamState_connected) {
        deref(s);
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE));
        return -1;
    }

    buf = flex_buffer_from(FLEX_PADDING_LEN, data, len);
    sent = s->pipeline.write(&s->pipeline, buf);
    if (sent < 0)
        IOEX_set_error((int)sent);
    else
        vlogD("Session: Stream %d sent %d bytes data.", s->id, (int)len);

    deref(s);
    return sent < 0 ? -1: sent;
}

int IOEX_stream_get_type(IOEXSession *ws, int stream, IOEXStreamType *type)
{
    IOEXStream *s;

    if (!ws || stream <= 0 || !type) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    s = get_stream(ws, stream);
    if (!s) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    *type = s->type;
    deref(s);

    return 0;
}

int IOEX_stream_get_state(IOEXSession *ws, int stream, IOEXStreamState *state)
{
    IOEXStream *s;

    if (!ws || stream <= 0 || !state) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    s = get_stream(ws, stream);
    if (!s) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    *state = s->state;
    deref(s);

    return 0;
}

int IOEX_stream_get_transport_info(IOEXSession *ws, int stream, IOEXTransportInfo *info)
{
    int rc;
    IOEXStream *s;

    if (!ws || stream <= 0 || !info) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    s = get_stream(ws, stream);
    if (!s) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    if (s->state != IOEXStreamState_connected) {
        deref(s);
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE));
        return -1;
    }

    rc = s->get_info(s, info);
    if (rc < 0)
        IOEX_set_error(rc);

    deref(s);
    return rc < 0 ? -1 : 0;
}

int IOEX_stream_open_channel(IOEXSession *ws, int stream, const char *cookie)
{
    int rc;
    IOEXStream *s;

    if (!ws || stream <= 0) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    s = get_stream(ws, stream);
    if (!s) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    if (s->state != IOEXStreamState_connected) {
        deref(s);
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE));
        return -1;
    }

    if (!s->mux)
        rc = IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE);
    else
        rc = s->mux->channel.open(s->mux, ChannelType_User, cookie, 0);

    if (rc < 0)
        IOEX_set_error(rc);

    deref(s);
    return rc < 0 ? -1 : rc;
}

int IOEX_stream_close_channel(IOEXSession *ws, int stream, int channel)
{
    int rc;
    IOEXStream *s;

    if (!ws || stream <= 0) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    s = get_stream(ws, stream);
    if (!s) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    if (!s->mux)
        rc = IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE);
    else
        rc = s->mux->channel.close(s->mux, channel);

    if (rc < 0)
        IOEX_set_error(rc);

    deref(s);
    return rc < 0 ? -1 : 0;
}

ssize_t IOEX_stream_write_channel(IOEXSession *ws, int stream,
                                 int channel, const void *data, size_t len)
{
    ssize_t written;
    IOEXStream *s;

    if (!ws || stream <= 0 || channel < 0 || !data || !len ||
        len > IOEX_MAX_USER_DATA_LEN) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    s = get_stream(ws, stream);
    if (!s) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    if (s->state != IOEXStreamState_connected) {
        deref(s);
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE));
        return -1;
    }

    if (!s->mux)
        written = (ssize_t)IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE);
    else {
        FlexBuffer *buf = flex_buffer_from(FLEX_PADDING_LEN, data, len);

        written = s->mux->channel.write(s->mux, channel, buf);
    }

    if (written < 0)
        IOEX_set_error((int)written);

    deref(s);
    return written;
}

int IOEX_stream_pend_channel(IOEXSession *ws, int stream, int channel)
{
    int rc;
    IOEXStream *s;

    if (!ws || stream <= 0 || channel <= 0) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    s = get_stream(ws, stream);
    if (!s) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    if (!s->mux)
        rc = IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE);
    else
        rc = s->mux->channel.pend(s->mux, channel);

    if (rc < 0)
        IOEX_set_error(rc);

    deref(s);
    return rc < 0 ? -1 : 0;
}

int IOEX_stream_resume_channel(IOEXSession *ws, int stream, int channel)
{
    int rc;
    IOEXStream *s;

    if (!ws || stream <= 0 || channel <= 0) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    s = get_stream(ws, stream);
    if (!s) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    if (!s->mux)
        rc = IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE);
    else
        rc = s->mux->channel.resume(s->mux, channel);

    if (rc < 0)
        IOEX_set_error(rc);

    deref(s);
    return rc < 0 ? -1 : 0;
}

int IOEX_session_add_service(IOEXSession *ws, const char *service,
                            PortForwardingProtocol protocol,
                            const char *host, const char *port)
{
    Service *svc;
    char *p;

    size_t service_len;
    size_t host_len;
    size_t port_len;

    if (!ws || !service || !*service || !host || !*host|| !port || !*port ||
        protocol != PortForwardingProtocol_TCP) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (!ws->portforwarding.services) {
        ws->portforwarding.services = services_create(8);
        if (!ws->portforwarding.services) {
            IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
            return -1;
        }
    }

    if (services_exist(ws->portforwarding.services, service)){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_ALREADY_EXIST));
        return -1;
    }

    service_len = strlen(service);
    host_len = strlen(host);
    port_len = strlen(port);

    svc = rc_zalloc(sizeof(Service) + service_len + host_len + port_len + 3, NULL);
    if (!svc) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return -1;
    }

    p = svc->data;
    strcpy(p, service);
    svc->name = p;

    p += (service_len + 1);
    strcpy(p, host);
    svc->host = p;

    p += (host_len + 1);
    strcpy(p, port);
    svc->port = p;

    svc->protocol = protocol;

    services_put(ws->portforwarding.services, svc);
    deref(svc);

    return 0;
}

void IOEX_session_remove_service(IOEXSession *ws, const char *service)
{
    if (!ws || !service || !*service) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return;
    }

    if (ws->portforwarding.services)
        services_remove(ws->portforwarding.services, service);
}

int IOEX_stream_open_port_forwarding(IOEXSession *ws, int stream,
        const char *service, PortForwardingProtocol protocol,
        const char *host, const char *port)
{
    int rc;
    IOEXStream *s;

    if (!ws || stream <= 0 || !service || !*service || !port || !*port ||
        protocol != PortForwardingProtocol_TCP) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    s = get_stream(ws, stream);
    if (!s) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    if (protocol == PortForwardingProtocol_TCP && !s->reliable) {
        deref(s);
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE));
        return -1;
    }

    if (!host || !*host)
        host = "127.0.0.1"; // Default bind to localhost only

    if (!s->mux)
        rc = IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE);
    else
        rc = s->mux->portforwarding.open(s->mux, service, protocol, host, port);

    if (rc < 0)
        IOEX_set_error(rc);

    deref(s);
    return rc < 0 ? -1 : rc;
}

int IOEX_stream_close_port_forwarding(IOEXSession *ws, int stream,
                                    int portforwarding)
{
    int rc;
    IOEXStream *s;

    if (!ws || stream <= 0 || portforwarding <= 0) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    s = get_stream(ws, stream);
    if (!s) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    if (!s->mux)
        rc = IOEX_GENERAL_ERROR(IOEXERR_WRONG_STATE);
    else
        rc = s->mux->portforwarding.close(s->mux, portforwarding);

    if (rc < 0)
        IOEX_set_error(rc);

    deref(s);
    return rc < 0 ? -1 : 0;
}
