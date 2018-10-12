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
#include <stdarg.h>
#include <limits.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <rc_mem.h>
#include <base58.h>
#include <vlog.h>
#include <crypto.h>
#include <linkedlist.h>

#include "IOEX_carrier.h"
#include "IOEX_carrier_impl.h"
#include "IOEX_turnserver.h"
#include "friends.h"
#include "tcallbacks.h"
#include "thistory.h"
#include "IOEXcp.h"
#include "dht.h"

#define TURN_SERVER_PORT                ((uint16_t)3478)
#define TURN_SERVER_USER_SUFFIX         "auth.tox"
#define TURN_REALM                      "IOEX.org"

const char* IOEX_get_version(void)
{
    return "IOEXCarrier-5.0.1";
}

static bool is_valid_key(const char *key)
{
    char result[DHT_PUBLIC_KEY_SIZE << 1];
    ssize_t len;

    len = base58_decode(key, strlen(key), result, sizeof(result));
    return len == DHT_PUBLIC_KEY_SIZE;
}

bool IOEX_id_is_valid(const char *id)
{
    if (!id || !*id) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return false;
    }

    return is_valid_key(id);
}

static uint16_t address_checksum(const uint8_t *address, uint32_t len)
{
    uint8_t checksum[2] = {0};
    uint16_t check;
    uint32_t i;

    for (i = 0; i < len; ++i)
        checksum[i % 2] ^= address[i];

    memcpy(&check, checksum, sizeof(check));
    return check;
}

static bool is_valid_address(const char *address)
{
    uint8_t addr[DHT_ADDRESS_SIZE];
    uint16_t check, checksum;
    ssize_t len;

    len = base58_decode(address, strlen(address), addr, sizeof(addr));
    if (len != DHT_ADDRESS_SIZE)
        return false;

    memcpy(&check, addr + DHT_PUBLIC_KEY_SIZE + sizeof(uint32_t), sizeof(check));
    checksum = address_checksum(addr, DHT_ADDRESS_SIZE - sizeof(checksum));

    return checksum == check;
}

bool IOEX_address_is_valid(const char *address)
{
    if (!address || !*address) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return false;
    }

    return is_valid_address(address);
}

char *IOEX_get_id_by_address(const char *address, char *userid, size_t len)
{
    uint8_t addr[DHT_ADDRESS_SIZE];
    ssize_t addr_len;
    char *ret_userid;
    size_t userid_len = IOEX_MAX_ID_LEN + 1;

    if (len <= IOEX_MAX_ID_LEN) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return NULL;
    }

    addr_len = base58_decode(address, strlen(address), addr, sizeof(addr));
    if (addr_len != DHT_ADDRESS_SIZE) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return NULL;
    }

    memset(userid, 0, len);
    ret_userid = base58_encode(addr, DHT_PUBLIC_KEY_SIZE, userid, &userid_len);
    if (ret_userid == NULL) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return NULL;
    }

    return ret_userid;
}

void IOEX_log_init(IOEXLogLevel level, const char *log_file,
                  void (*log_printer)(const char *format, va_list args))
{
#if !defined(__ANDROID__)
    vlog_init(level, log_file, log_printer);
#endif
}

static
int get_friend_number(IOEXCarrier *w, const char *friendid, uint32_t *friend_number)
{
    uint8_t public_key[DHT_PUBLIC_KEY_SIZE];
    ssize_t len;
    int rc;

    assert(w);
    assert(friendid);
    assert(friend_number);

    len = base58_decode(friendid, strlen(friendid), public_key, sizeof(public_key));
    if (len != DHT_PUBLIC_KEY_SIZE) {
        vlogE("Carrier: friendid %s not base58 encoded.", friendid);
        return IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS);
    }

    rc = dht_get_friend_number(&w->dht, public_key, friend_number);
    if (rc < 0) {
        //vlogE("Carrier: friendid %s is not friend yet.", friendid);
        return IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST);
    }

    return rc;
}

static void fill_empty_user_desc(IOEXCarrier *w)
{
    IOEXCP *cp;
    uint8_t *data;
    size_t data_len;

    assert(w);

    cp = IOEXcp_create(IOEXCP_TYPE_USERINFO, NULL);
    if (!cp) {
        vlogE("Carrier: Out of memory!!!");
        return;
    }

    IOEXcp_set_has_avatar(cp, false);
    IOEXcp_set_name(cp, "");
    IOEXcp_set_descr(cp, "");
    IOEXcp_set_gender(cp, "");
    IOEXcp_set_phone(cp, "");
    IOEXcp_set_email(cp, "");
    IOEXcp_set_region(cp, "");

    data = IOEXcp_encode(cp, &data_len);
    IOEXcp_free(cp);

    if (!data) {
        vlogE("Carrier: Encode user desc to packet error");
        return;
    }

    dht_self_set_desc(&w->dht, data, data_len);
    free(data);
}

static
int unpack_user_desc(const uint8_t *desc, size_t desc_len, IOEXUserInfo *info,
                     bool *changed)
{
    IOEXCP *cp;
    const char *name;
    const char *descr;
    const char *gender;
    const char *phone;
    const char *email;
    const char *region;
    bool has_avatar;
    bool did_changed = false;

    assert(desc);
    assert(desc_len > 0);
    assert(info);

    cp = IOEXcp_decode(desc, desc_len);
    if (!cp)
        return -1;

    if (IOEXcp_get_type(cp) != IOEXCP_TYPE_USERINFO) {
        IOEXcp_free(cp);
        vlogE("Carrier: Unkown userinfo type format.");
        return -1;
    }

    has_avatar = IOEXcp_get_has_avatar(cp);

    name   = IOEXcp_get_name(cp)   ? IOEXcp_get_name(cp) : "";
    descr  = IOEXcp_get_descr(cp)  ? IOEXcp_get_descr(cp) : "";
    gender = IOEXcp_get_gender(cp) ? IOEXcp_get_gender(cp) : "";
    phone  = IOEXcp_get_phone(cp)  ? IOEXcp_get_phone(cp) : "";
    email  = IOEXcp_get_email(cp)  ? IOEXcp_get_email(cp) : "";
    region = IOEXcp_get_region(cp) ? IOEXcp_get_region(cp) : "";

    if (strcmp(info->name, name)) {
        strcpy(info->name, name);
        did_changed = true;
    }

    if (strcmp(info->description, descr)) {
        strcpy(info->description, descr);
        did_changed = true;
    }

    if (strcmp(info->gender, gender)) {
        strcpy(info->gender, gender);
        did_changed = true;
    }

    if (strcmp(info->phone, phone)) {
        strcpy(info->phone, phone);
        did_changed = true;
    }

    if (strcmp(info->email, email)) {
        strcpy(info->email, email);
        did_changed = true;
    }

    if (strcmp(info->region, region)) {
        strcpy(info->region, region);
        did_changed = true;
    }

    if (info->has_avatar != has_avatar) {
        info->has_avatar = has_avatar;
        did_changed = true;
    }

    IOEXcp_free(cp);

    if (changed)
        *changed = did_changed;

    return 0;
}

static IOEXPresenceStatus get_presence_status(int user_status)
{
    IOEXPresenceStatus presence;

    if (user_status < IOEXPresenceStatus_None)
        presence = IOEXPresenceStatus_None;
    else if (user_status > IOEXPresenceStatus_Busy)
        presence = IOEXPresenceStatus_Busy;
    else
        presence = (IOEXPresenceStatus)user_status;

    return presence;
}

static void get_self_info_cb(const uint8_t *address, const uint8_t *public_key,
                             int user_status,
                             const uint8_t *desc, size_t desc_len,
                             void *context)
{
    IOEXCarrier *w = (IOEXCarrier *)context;
    IOEXUserInfo *ui = &w->me;
    size_t text_len;

    memcpy(w->address, address, DHT_ADDRESS_SIZE);
    memcpy(w->public_key, public_key, DHT_PUBLIC_KEY_SIZE);

    text_len = sizeof(w->base58_addr);
    base58_encode(address, DHT_ADDRESS_SIZE, w->base58_addr, &text_len);
    text_len = sizeof(ui->userid);
    base58_encode(public_key, DHT_PUBLIC_KEY_SIZE, ui->userid, &text_len);

    w->presence_status = get_presence_status(user_status);

    if (desc_len > 0)
        unpack_user_desc(desc, desc_len, ui, NULL);
    else
        fill_empty_user_desc(w);
}

static bool friends_iterate_cb(uint32_t friend_number,
                               const uint8_t *public_key,
                               int user_status,
                               const uint8_t *desc, size_t desc_len,
                               void *context)
{
    IOEXCarrier *w = (IOEXCarrier *)context;
    FriendInfo *fi;
    IOEXUserInfo *ui;
    size_t _len = sizeof(ui->userid);
    int rc;

    assert(friend_number != UINT32_MAX);

    fi = (FriendInfo *)rc_zalloc(sizeof(FriendInfo), NULL);
    if (!fi)
        return false;

    ui = &fi->info.user_info;
    base58_encode(public_key, DHT_PUBLIC_KEY_SIZE, ui->userid, &_len);

    if (desc_len > 0) {
        rc = unpack_user_desc(desc, desc_len, ui, NULL);
        if (rc < 0) {
            deref(fi);
            return false;
        }
    }

    fi->info.status = IOEXConnectionStatus_Disconnected;
    fi->info.presence = get_presence_status(user_status);
    fi->friend_number = friend_number;

    // Label will be synched later from data file.

    friends_put(w->friends, fi);

    deref(fi);

    return true;
}

static const uint32_t PERSISTENCE_MAGIC = 0x0E0C0D0A;
static const uint32_t PERSISTENCE_REVISION = 2;

static const char *data_filename = "carrier.data";
static const char *old_dhtdata_filename = "dhtdata";
static const char *old_IOEXdata_filename = "IOEXdata";

#define MAX_PERSISTENCE_SECTION_SIZE        (16 * 1024 *1024)

#define ROUND256(s)     (((((s) + 64) >> 8) + 1) << 8)

typedef struct persistence_data {
    size_t dht_savedata_len;
    const uint8_t *dht_savedata;
    size_t extra_savedata_len;
    const uint8_t *extra_savedata;
} persistence_data;

static int convert_old_dhtdata(const char *data_location)
{
    uint8_t *buf;
    uint8_t *pos;
    char *dhtdata_filename;
    char *IOEXdata_filename;
    char *journal_filename;
    char *filename;
    struct stat st;
    uint32_t val;
    int fd;

    size_t dht_data_len;
    size_t extra_data_len;
    size_t total_len;

    assert(data_location);

    dhtdata_filename = (char *)alloca(strlen(data_location) + strlen(old_dhtdata_filename) + 4);
    sprintf(dhtdata_filename, "%s/%s", data_location, old_dhtdata_filename);
    IOEXdata_filename = (char *)alloca(strlen(data_location) + strlen(old_IOEXdata_filename) + 4);
    sprintf(IOEXdata_filename, "%s/%s", data_location, old_IOEXdata_filename);

    if (stat(dhtdata_filename, &st) < 0)
        return IOEX_SYS_ERROR(errno);

    dht_data_len = st.st_size;

    if (stat(IOEXdata_filename, &st) < 0 ||
            st.st_size < (PUBLIC_KEY_BYTES + sizeof(uint32_t)))
        extra_data_len = 0;
    else
        extra_data_len = (st.st_size - PUBLIC_KEY_BYTES - sizeof(uint32_t));

    total_len = 256 + ROUND256(dht_data_len) + ROUND256(extra_data_len);
    buf = (uint8_t *)calloc(total_len, 1);
    if (!buf)
        return IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY);

    pos = buf + 256;

    fd = open(dhtdata_filename, O_RDONLY);
    if (fd < 0) {
        free(buf);
        return IOEX_SYS_ERROR(errno);
    }

    if (read(fd, pos, dht_data_len) != dht_data_len) {
        free(buf);
        close(fd);
        return IOEX_SYS_ERROR(errno);
    }

    close(fd);

    if (extra_data_len) {
        pos += ROUND256(dht_data_len);

        fd = open(IOEXdata_filename, O_RDONLY);
        if (fd < 0) {
            extra_data_len = 0;
            goto write_data;
        }

        // Skip public key
        lseek(fd, PUBLIC_KEY_BYTES, SEEK_SET);
        // read friends count
        if (read(fd, &val, sizeof(val)) != sizeof(val)) {
            close(fd);
            extra_data_len = 0;
            goto write_data;
        }

        if (val > 0) {
            if (read(fd, pos, extra_data_len) != extra_data_len) {
                close(fd);
                memset(pos, 0, extra_data_len);
                extra_data_len = 0;
                goto write_data;
            }

            uint8_t *rptr = pos;
            uint8_t *wptr = pos;
            int i;

            for (i = 0; i < val; i++) {
                uint32_t id = *(uint32_t *)rptr;
                rptr += sizeof(uint32_t);
                size_t label_len = strlen((const char *)rptr);
                if (label_len == 0) {
                    rptr++;
                    continue;
                }

                id = htonl(id);
                memcpy(wptr, &id, sizeof(id));
                wptr += sizeof(uint32_t);
                memmove(wptr, rptr, label_len + 1);
                wptr += (label_len + 1);
                rptr += (label_len + 1);
            }

            extra_data_len = wptr - pos;
            memset(wptr, 0, rptr - wptr);
        }

        close(fd);
    }

write_data:

    total_len = 256 + ROUND256(dht_data_len) + ROUND256(extra_data_len);

    pos = buf;
    val = htonl(PERSISTENCE_MAGIC);
    memcpy(pos, &val, sizeof(uint32_t));

    pos += sizeof(uint32_t);
    val = htonl(PERSISTENCE_REVISION);
    memcpy(pos, &val, sizeof(uint32_t));

    pos += sizeof(uint32_t);
    val = htonl((uint32_t)dht_data_len);
    memcpy(pos, &val, sizeof(uint32_t));

    pos += sizeof(uint32_t);
    val = htonl((uint32_t)extra_data_len);
    memcpy(pos, &val, sizeof(uint32_t));

    pos = buf + 256;
    sha256(pos, total_len - 256, buf + (sizeof(uint32_t) * 4), SHA256_BYTES);

    filename = (char *)alloca(strlen(data_location) + strlen(data_filename) + 4);
    sprintf(filename, "%s/%s", data_location, data_filename);
    journal_filename = (char *)alloca(strlen(data_location) + strlen(data_filename) + 16);
    sprintf(journal_filename, "%s/%s.journal", data_location, data_filename);

    fd = open(journal_filename, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        free(buf);
        return IOEX_SYS_ERROR(errno);
    }

    if (write(fd, buf, total_len) != total_len) {
        close(fd);
        remove(journal_filename);
        return IOEX_SYS_ERROR(errno);
    }

    if (fsync(fd) < 0) {
        close(fd);
        remove(journal_filename);
        return IOEX_SYS_ERROR(errno);
    }

    close(fd);
    free(buf);

    remove(dhtdata_filename);
    remove(IOEXdata_filename);
    remove(filename);
    rename(journal_filename, filename);

    return 0;
}

static int _load_persistence_data_i(int fd, persistence_data *data)
{
    struct stat st;
    uint32_t val;
    size_t dht_data_len;
    size_t extra_data_len;
    unsigned char p_sum[SHA256_BYTES];
    unsigned char c_sum[SHA256_BYTES];

    uint8_t *buf;

    if (fstat(fd, &st) < 0) {
        vlogW("Load persistence data failed, stat files error(%d).", errno);
        return -1;
    }

    if (st.st_size < 256) {
        vlogW("Load persistence data failed, corrupt file.");
        return -1;
    }

    if (read(fd, (void *)&val, sizeof(val)) != sizeof(val)) {
        vlogW("Load persistence data failed, read error(%d).", errno);
        return -1;
    }
    val = ntohl(val);
    if (val != PERSISTENCE_MAGIC) {
        vlogW("Load persistence data failed, corrupt file.");
        return -1;
    }

    if (read(fd, (void *)&val, sizeof(val)) != sizeof(val)) {
        vlogW("Load persistence data failed, read error(%d).", errno);
        return -1;
    }
    val = ntohl(val);
    if (val != PERSISTENCE_REVISION) {
        vlogW("Load persistence data failed, unsupported date file version.");
        return -1;
    }

    if (read(fd, (void *)&val, sizeof(val)) != sizeof(val)) {
        vlogW("Load persistence data failed, read error(%d).", errno);
        return -1;
    }
    dht_data_len = ntohl(val);
    if (dht_data_len > MAX_PERSISTENCE_SECTION_SIZE) {
        vlogW("Load persistence data failed, corrupt file.");
        return -1;
    }

    if (read(fd, (void *)&val, sizeof(val)) != sizeof(val)) {
        vlogW("Load persistence data failed, read error(%d).", errno);
        return -1;
    }
    extra_data_len = ntohl(val);
    if (extra_data_len > MAX_PERSISTENCE_SECTION_SIZE) {
        vlogW("Load persistence data failed, corrupt file.");
        return -1;
    }

    if (st.st_size != 256 + ROUND256(dht_data_len) + ROUND256(extra_data_len)) {
        vlogW("Load persistence data failed, corrupt file.");
        return -1;
    }

    if (read(fd, p_sum, sizeof(p_sum)) != sizeof(p_sum)) {
        vlogW("Load persistence data failed, read error(%d).", errno);
        return -1;
    }

    buf = (uint8_t *)malloc(st.st_size - 256);
    if (!buf) {
        vlogW("Load persistence data failed, out of memory.");
        return -1;
    }

    lseek(fd, 256, SEEK_SET);
    if (read(fd, buf, st.st_size - 256) != (st.st_size - 256)) {
        vlogW("Load persistence data failed, read error(%d).", errno);
        free(buf);
        return -1;
    }

    sha256(buf, st.st_size - 256, c_sum, sizeof(c_sum));
    if (memcmp(p_sum, c_sum, SHA256_BYTES) != 0) {
        vlogW("Load persistence data failed, corrupt file.");
        free(buf);
        return -1;
    }

    data->dht_savedata_len = dht_data_len;
    data->dht_savedata = (const uint8_t *)buf;
    data->extra_savedata_len = extra_data_len;
    data->extra_savedata = (const uint8_t *)buf + ROUND256(dht_data_len);

    return 0;
}

#define FAILBACK_OR_RETURN(rc)          \
    if (journal) {                      \
        journal = 0;                    \
        goto failback;                  \
    } else {                            \
        return rc;                      \
    }

static int load_persistence_data(const char *data_location, persistence_data *data)
{
    char *filename;
    int journal = 1;
    int fd;
    int rc;

    assert(data_location);
    assert(data);

    filename = (char *)alloca(strlen(data_location) + strlen(data_filename) + 16);

failback:
    // Load from journal file first.
    if (journal)
        sprintf(filename, "%s/%s.journal", data_location, data_filename);
    else
        sprintf(filename, "%s/%s", data_location, data_filename);

    if (access(filename, F_OK | R_OK) < 0) {
        if (journal) {
            journal = 0;
            goto failback;
        } else {
            sprintf(filename, "%s/%s", data_location, old_dhtdata_filename);

            if (access(filename, F_OK | R_OK) < 0)
                return -1;

            vlogT("Try convert old persistence data...");
            if (convert_old_dhtdata(data_location) < 0) {
                vlogE("Convert old persistence data failed.");
                return -1;
            }

            vlogT("Convert old persistence data to current version.");
            goto failback;
        }
    }

    vlogD("Try to loading persistence data from: %s.", filename);

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        vlogD("Loading persistence data failed, cannot open file.");
        FAILBACK_OR_RETURN(-1);
    }

    rc = _load_persistence_data_i(fd, data);
    close(fd);

    if (rc < 0) {
        FAILBACK_OR_RETURN(rc);
    }

    if (rc == 0 && journal) {
        char *journal_filename = filename;
        char *filename = (char *)alloca(strlen(data_location) + strlen(data_filename) + 16);
        sprintf(filename, "%s/%s", data_location, data_filename);

        remove(filename);
        rename(journal_filename, filename);
    }

    return rc;
}

static void apply_extra_data(IOEXCarrier *w, const uint8_t *extra_savedata, size_t extra_savedata_len)
{
    const uint8_t *pos = extra_savedata;

    while (extra_savedata_len > 0) {
        uint32_t friend_number;
        char *label;
        size_t label_len;
        FriendInfo *fi;

        friend_number = ntohl(*(uint32_t *)pos);
        pos += sizeof(uint32_t);
        label = (char *)pos;
        label_len = strlen(label);
        pos += label_len + 1;

        if (label_len == 0)
            break;

        fi = friends_get(w->friends, friend_number);
        if (fi) {
            strcpy(fi->info.label, label);
            deref(fi);
        }

        extra_savedata_len -= (sizeof(uint32_t) + label_len + 1);
    }
}

static void free_persistence_data(persistence_data *data)
{
    if (data && data->dht_savedata)
        free((void *)data->dht_savedata);
}

static int _mkdir(const char *path, mode_t mode)
{
    struct stat st;
    int rc = 0;

    if (stat(path, &st) != 0) {
        /* Directory does not exist. EEXIST for race condition */
        if (mkdir(path, mode) != 0 && errno != EEXIST)
            rc = -1;
    } else if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        rc = -1;
    }

    return rc;
}

static int mkdirs(const char *path, mode_t mode)
{
    int rc = 0;
    char *pp;
    char *sp;
    char copypath[PATH_MAX];

    strncpy(copypath, path, sizeof(copypath));
    copypath[sizeof(copypath) - 1] = 0;

    pp = copypath;
    while (rc == 0 && (sp = strchr(pp, '/')) != 0) {
        if (sp != pp) {
            /* Neither root nor double slash in path */
            *sp = '\0';
            rc = _mkdir(copypath, mode);
            *sp = '/';
        }
        pp = sp + 1;
    }

    if (rc == 0)
        rc = _mkdir(path, mode);

    return rc;
}

static size_t get_extra_savedata_size(IOEXCarrier *w)
{
    HashtableIterator it;
    size_t total_len = 0;

    assert(w);
    assert(w->friends);

    friends_iterate(w->friends, &it);
    while(friends_iterator_has_next(&it)) {
        FriendInfo *fi;

        if (friends_iterator_next(&it, &fi) == 1) {
            size_t label_len = strlen(fi->info.label);
            if (label_len)
                total_len += sizeof(uint32_t) + label_len + 1;

            deref(fi);
        }
    }

    return total_len;
}

static void get_extra_savedata(IOEXCarrier *w, void *data, size_t len)
{
    HashtableIterator it;
    uint8_t *pos = (uint8_t *)data;

    assert(w);
    assert(w->friends);
    assert(data);

    friends_iterate(w->friends, &it);
    while(friends_iterator_has_next(&it) && len > 0) {
        FriendInfo *fi;

        if (friends_iterator_next(&it, &fi) == 1) {
            uint32_t nid;
            size_t label_len = strlen(fi->info.label);
            if (label_len) {
                if (len < (sizeof(uint32_t) + label_len + 1))
                    break;

                nid = htonl(fi->friend_number);
                memcpy(pos, &nid, sizeof(uint32_t));
                pos += sizeof(uint32_t);
                memcpy(pos, fi->info.label, label_len + 1);
                pos += (label_len + 1);

                len -= (sizeof(uint32_t) + label_len + 1);
            }

            deref(fi);
        }
    }

    return;
}

static int store_persistence_data(IOEXCarrier *w)
{
    uint8_t *buf;
    uint8_t *pos;
    char *journal_filename;
    char *filename;
    uint32_t val;
    int fd;
    int rc;

    size_t dht_data_len;
    size_t extra_data_len;
    size_t total_len;

    assert(w);

    dht_data_len = dht_get_savedata_size(&w->dht);
    extra_data_len = get_extra_savedata_size(w);
    total_len = 256 + ROUND256(dht_data_len) + ROUND256(extra_data_len);

    buf = (uint8_t *)calloc(total_len, 1);
    if (!buf)
        return IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY);

    pos = buf;
    val = htonl(PERSISTENCE_MAGIC);
    memcpy(pos, &val, sizeof(uint32_t));

    pos += sizeof(uint32_t);
    val = htonl(PERSISTENCE_REVISION);
    memcpy(pos, &val, sizeof(uint32_t));

    pos += sizeof(uint32_t);
    val = htonl((uint32_t)dht_data_len);
    memcpy(pos, &val, sizeof(uint32_t));

    pos += sizeof(uint32_t);
    val = htonl((uint32_t)extra_data_len);
    memcpy(pos, &val, sizeof(uint32_t));

    pos = buf + 256;
    dht_get_savedata(&w->dht, pos);
    pos += ROUND256(dht_data_len);
    get_extra_savedata(w, pos, ROUND256(extra_data_len));

    pos = buf + 256;
    sha256(pos, total_len - 256, buf + (sizeof(uint32_t) * 4), SHA256_BYTES);

    rc = mkdirs(w->pref.data_location, S_IRWXU);
    if (rc < 0) {
        free(buf);
        return IOEX_SYS_ERROR(errno);
    }

    filename = (char *)alloca(strlen(w->pref.data_location) + strlen(data_filename) + 4);
    sprintf(filename, "%s/%s", w->pref.data_location, data_filename);
    journal_filename = (char *)alloca(strlen(w->pref.data_location) + strlen(data_filename) + 16);
    sprintf(journal_filename, "%s/%s.journal", w->pref.data_location, data_filename);

    fd = open(journal_filename, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        free(buf);
        return IOEX_SYS_ERROR(errno);
    }

    if (write(fd, buf, total_len) != total_len) {
        close(fd);
        remove(journal_filename);
        return IOEX_SYS_ERROR(errno);
    }

    if (fsync(fd) < 0) {
        close(fd);
        remove(journal_filename);
        return IOEX_SYS_ERROR(errno);
    }

    close(fd);
    free(buf);

    remove(filename);
    rename(journal_filename, filename);

    return 0;
}

static void IOEX_destroy(void *argv)
{
    IOEXCarrier *w = (IOEXCarrier *)argv;

    if (w->pref.data_location)
        free(w->pref.data_location);

    if (w->pref.bootstraps)
        free(w->pref.bootstraps);

    if (w->tcallbacks)
        deref(w->tcallbacks);

    if (w->thistory)
        deref(w->thistory);

    if (w->friends)
        deref(w->friends);

    if (w->friend_events)
        deref(w->friend_events);

    if (w->file_senders)
        deref(w->file_senders);

    if (w->file_receivers)
        deref(w->file_receivers);

    dht_kill(&w->dht);
}

IOEXCarrier *IOEX_new(const IOEXOptions *opts,
                 IOEXCallbacks *callbacks, void *context)
{
    IOEXCarrier *w;
    persistence_data data;
    int rc;
    int i;

    if (!opts) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return NULL;
    }

    if (!opts->persistent_location || !*opts->persistent_location) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return NULL;
    }

    w = (IOEXCarrier *)rc_zalloc(sizeof(IOEXCarrier), IOEX_destroy);
    if (!w) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return NULL;
    }

    w->pref.udp_enabled = opts->udp_enabled;
    w->pref.data_location = strdup(opts->persistent_location);
    w->pref.bootstraps_size = opts->bootstraps_size;

    w->pref.bootstraps = (BootstrapNodeBuf *)calloc(1, sizeof(BootstrapNodeBuf)
                         * opts->bootstraps_size);
    if (!w->pref.bootstraps) {
        deref(w);
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return NULL;
    }

    for (i = 0; i < opts->bootstraps_size; i++) {
        BootstrapNode *b = &opts->bootstraps[i];
        BootstrapNodeBuf *bi = &w->pref.bootstraps[i];
        char *endptr = NULL;
        ssize_t len;

        if (b->ipv4 && strlen(b->ipv4) > MAX_IPV4_ADDRESS_LEN) {
            vlogE("Carrier: Bootstrap ipv4 address (%s) too long", b->ipv4);
            deref(w);
            IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
            return NULL;
        }

        if (b->ipv6 && strlen(b->ipv6) > MAX_IPV6_ADDRESS_LEN) {
            vlogE("Carrier: Bootstrap ipv4 address (%s) too long", b->ipv6);
            deref(w);
            IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
            return NULL;
        }

        if (!b->ipv4 && !b->ipv6) {
            vlogE("Carrier: Bootstrap ipv4 and ipv6 address both empty");
            deref(w);
            IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
            return NULL;
        }

        if (b->ipv4)
            strcpy(bi->ipv4, b->ipv4);
        if (b->ipv6)
            strcpy(bi->ipv6, b->ipv6);

        bi->port = (int)strtol(b->port, &endptr, 10);
        if (*endptr) {
            vlogE("Carrier: Invalid bootstrap port value (%s)", b->port);
            deref(w);
            IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
            return NULL;
        }

        len = base58_decode(b->public_key, strlen(b->public_key), bi->public_key,
                            sizeof(bi->public_key));
        if (len != DHT_PUBLIC_KEY_SIZE) {
            vlogE("Carrier: Invalid bootstrap public key (%s)", b->public_key);
            deref(w);
            IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
            return NULL;
        }
    }

    memset(&data, 0, sizeof(data));
    load_persistence_data(opts->persistent_location, &data);

    rc = dht_new(data.dht_savedata, data.dht_savedata_len, w->pref.udp_enabled, &w->dht);
    if (rc < 0) {
        free_persistence_data(&data);
        deref(w);
        IOEX_set_error(rc);
        return NULL;
    }

    w->friends = friends_create();
    if (!w->friends) {
        free_persistence_data(&data);
        deref(w);
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return NULL;
    }

    w->friend_events = list_create(1, NULL);
    if (!w->friend_events) {
        free_persistence_data(&data);
        deref(w);
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return NULL;
    }

    w->file_senders = list_create(1, NULL);
    if (!w->file_senders) {
        free_persistence_data(&data);
        deref(w);
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return NULL;
    }

    w->file_receivers = list_create(1, NULL);
    if (!w->file_receivers) {
        free_persistence_data(&data);
        deref(w);
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return NULL;
    }

    w->tcallbacks = transacted_callbacks_create(32);
    if (!w->tcallbacks) {
        free_persistence_data(&data);
        deref(w);
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return NULL;
    }

    w->thistory = transaction_history_create(32);
    if (!w->thistory) {
        free_persistence_data(&data);
        deref(w);
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return NULL;
    }

    rc = dht_get_self_info(&w->dht, get_self_info_cb, w);
    if (rc < 0) {
        free_persistence_data(&data);
        deref(w);
        IOEX_set_error(rc);
        return NULL;
    }

    rc = dht_get_friends(&w->dht, friends_iterate_cb, w);
    if (rc < 0) {
        free_persistence_data(&data);
        deref(w);
        IOEX_set_error(rc);
        return NULL;
    }

    apply_extra_data(w, data.extra_savedata, data.extra_savedata_len);
    free_persistence_data(&data);

    store_persistence_data(w);

    srand((unsigned int)time(NULL));

    if (callbacks) {
        w->callbacks = *callbacks;
        w->context = context;
    }

    vlogI("Carrier: Carrier node created.");

    return w;
}

void IOEX_kill(IOEXCarrier *w)
{
    if (!w) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return;
    }

    if (w->running) {
        w->quit = 1;

        if (!pthread_equal(pthread_self(), w->main_thread))
            while(!w->quit) usleep(5000);
    }

    deref(w);

    vlogI("Carrier: Carrier node killed.");
}

static void notify_idle(IOEXCarrier *w)
{
    if (w->callbacks.idle)
        w->callbacks.idle(w, w->context);
}

static void notify_friends(IOEXCarrier *w)
{
    HashtableIterator it;

    friends_iterate(w->friends, &it);
    while(friends_iterator_has_next(&it)) {
        FriendInfo *fi;
        IOEXFriendInfo _fi;

        if (friends_iterator_next(&it, &fi) == 1) {
            if (w->callbacks.friend_list) {
                memcpy(&_fi, &fi->info, sizeof(IOEXFriendInfo));
                w->callbacks.friend_list(w, &_fi, w->context);
            }

            deref(fi);
        }
    }

    if (w->callbacks.friend_list)
        w->callbacks.friend_list(w, NULL, w->context);
}

static void notify_connection_cb(bool connected, void *context)
{
    IOEXCarrier *w = (IOEXCarrier *)context;

    if (!w->is_ready && connected) {
        w->is_ready = true;
        if (w->callbacks.ready)
            w->callbacks.ready(w, w->context);
    }

    w->connection_status = (connected ? IOEXConnectionStatus_Connected :
                                        IOEXConnectionStatus_Disconnected);

    if (w->callbacks.connection_status)
        w->callbacks.connection_status(w, w->connection_status, w->context);
}

static void notify_friend_info(IOEXCarrier *w, uint32_t friend_number,
                               IOEXFriendInfo *info)

{
    const char *userid;

    assert(w);
    assert(friend_number != UINT32_MAX);
    assert(info);

    userid = info->user_info.userid;

    if (friends_exist(w->friends, friend_number)) {
        if (w->callbacks.friend_info)
            w->callbacks.friend_info(w, userid, info, w->context);
    }
}

static
void notify_friend_description_cb(uint32_t friend_number, const uint8_t *desc,
                                  size_t length, void *context)
{
    IOEXCarrier *w = (IOEXCarrier *)context;
    FriendInfo *fi;
    IOEXUserInfo *ui;
    bool changed;

    assert(friend_number != UINT32_MAX);
    assert(desc);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        vlogE("Carrier: Unknown friend number %lu, friend description message "
              "dropped.", friend_number);
        return;
    }

    if (length == 0) {
        vlogW("Carrier: Empty description message from friend "
              "number %lu, dropped.", friend_number);
        deref(fi);
        return;
    }

    ui = &fi->info.user_info;
    unpack_user_desc(desc, length, ui, &changed);

    if (changed) {
        IOEXFriendInfo tmpfi;

        memcpy(&tmpfi, &fi->info, sizeof(tmpfi));
        notify_friend_info(w, friend_number, &tmpfi);
    }

    deref(fi);
}

static void notify_friend_connection(IOEXCarrier *w, const char *friendid,
                                     IOEXConnectionStatus status)
{
    assert(w);
    assert(friendid);

    if (w->callbacks.friend_connection)
        w->callbacks.friend_connection(w, friendid, status, w->context);
}

static
void notify_friend_connection_cb(uint32_t friend_number, bool connected,
                                 void *context)
{
    IOEXCarrier *w = (IOEXCarrier *)context;
    FriendInfo *fi;
    char tmpid[IOEX_MAX_ID_LEN + 1];
    IOEXConnectionStatus status;

    assert(friend_number != UINT32_MAX);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        vlogE("Carrier: Unknown friend number %lu, connection status message "
              "dropped (%s).", friend_number, connected ? "true":"false");
        return;
    }

    status = connected ? IOEXConnectionStatus_Connected :
                         IOEXConnectionStatus_Disconnected;

    if (status != fi->info.status) {
        fi->info.status = status;
        strcpy(tmpid, fi->info.user_info.userid);

        notify_friend_connection(w, tmpid, status);
    }

    deref(fi);
}

static void notify_friend_presence(IOEXCarrier *w, const char *friendid,
                                   IOEXPresenceStatus presence)
{
    assert(w);
    assert(friendid);

    if (w->callbacks.friend_presence)
        w->callbacks.friend_presence(w, friendid, presence, w->context);
}

static
void notify_friend_status_cb(uint32_t friend_number, int status,
                             void *context)
{
    IOEXCarrier *w = (IOEXCarrier *)context;
    FriendInfo *fi;
    char tmpid[IOEX_MAX_ID_LEN + 1];

    assert(friend_number != UINT32_MAX);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        vlogE("Carrier: Unknown friend number (%lu), friend presence message "
              "dropped.", friend_number);
        return;
    }

    if (status < IOEXPresenceStatus_None ||
        status > IOEXPresenceStatus_Busy) {
        vlogE("Carrier: Invalid friend status %d received, dropped it.", status);
        return;
    }

    if (status != fi->info.presence) {
        fi->info.presence = status;
        strcpy(tmpid, fi->info.user_info.userid);

        notify_friend_presence(w, tmpid, status);
    }

    deref(fi);
}

static
void notify_friend_request_cb(const uint8_t *public_key, const uint8_t* gretting,
                              size_t length, void *context)
{
    IOEXCarrier *w = (IOEXCarrier *)context;
    uint32_t friend_number;
    IOEXCP* cp;
    IOEXUserInfo ui;
    size_t _len = sizeof(ui.userid);
    const char *name;
    const char *descr;
    const char *hello;
    int rc;

    assert(public_key);
    assert(gretting && length > 0);

    rc = dht_get_friend_number(&w->dht, public_key, &friend_number);
    if (rc == 0 && friend_number != UINT32_MAX) {
        vlogW("Carrier: friend already exist, dropped friend request.");
        return;
    }

    cp = IOEXcp_decode(gretting, length);
    if (!cp) {
        vlogE("Carrier: Inavlid friend request, dropped this request.");
        return;
    }

    if (IOEXcp_get_type(cp) != IOEXCP_TYPE_FRIEND_REQUEST) {
        vlogE("Carrier: Invalid friend request, dropped this request.");
        IOEXcp_free(cp);
        return;
    }

    memset(&ui, 0, sizeof(ui));
    base58_encode(public_key, DHT_PUBLIC_KEY_SIZE, ui.userid, &_len);

    name  = IOEXcp_get_name(cp)  ? IOEXcp_get_name(cp)  : "";
    descr = IOEXcp_get_descr(cp) ? IOEXcp_get_descr(cp) : "";
    hello = IOEXcp_get_hello(cp) ? IOEXcp_get_hello(cp) : "";

    if (*name)
        strcpy(ui.name, name);
    if (*descr)
        strcpy(ui.description, descr);

    if (w->callbacks.friend_request)
        w->callbacks.friend_request(w, ui.userid, &ui, hello, w->context);

    IOEXcp_free(cp);
}

static void notify_friend_added(IOEXCarrier *w, IOEXFriendInfo *fi)
{
    FriendEvent *event;

    assert(w);
    assert(fi);

    store_persistence_data(w);

    event = (FriendEvent *)rc_alloc(sizeof(FriendEvent), NULL);
    if (event) {
        event->type = FriendEventType_Added;
        memcpy(&event->fi, fi, sizeof(*fi));

        event->le.data = event;
        list_push_tail(w->friend_events, &event->le);
        deref(event);
    }
}

static void notify_friend_removed(IOEXCarrier *w, IOEXFriendInfo *fi)
{
    FriendEvent *event;

    assert(w);
    assert(fi);

    store_persistence_data(w);

    event = (FriendEvent *)rc_alloc(sizeof(FriendEvent), NULL);
    if (event) {
        event->type = FriendEventType_Removed;
        memcpy(&event->fi, fi, sizeof(*fi));

        event->le.data = event;
        list_push_tail(w->friend_events, &event->le);
        deref(event);
    }
}

static void do_friend_event(IOEXCarrier *w, FriendEvent *event)
{
    assert(w);
    assert(event);

    switch(event->type) {
    case FriendEventType_Added:
        if (w->callbacks.friend_added)
            w->callbacks.friend_added(w, &event->fi, w->context);
        break;

    case FriendEventType_Removed:
        if (event->fi.status == IOEXConnectionStatus_Connected) {
            if (w->callbacks.friend_connection)
                w->callbacks.friend_connection(w, event->fi.user_info.userid,
                                IOEXConnectionStatus_Disconnected, w->context);
        }

        if (w->callbacks.friend_removed)
            w->callbacks.friend_removed(w, event->fi.user_info.userid, w->context);
        break;

    default:
        assert(0);
    }
}

static void do_friend_events(IOEXCarrier *w)
{
    List *events = w->friend_events;
    ListIterator it;

redo_events:
    list_iterate(events, &it);
    while (list_iterator_has_next(&it)) {
        FriendEvent *event;
        int rc;

        rc = list_iterator_next(&it, (void **)&event);
        if (rc == 0)
            break;

        if (rc == -1)
            goto redo_events;

        do_friend_event(w, event);
        list_iterator_remove(&it);

        deref(event);
    }
}

static
void handle_friend_message(IOEXCarrier *w, uint32_t friend_number, IOEXCP *cp)
{
    FriendInfo *fi;
    char friendid[IOEX_MAX_ID_LEN + 1];
    const char *name;
    const void *msg;
    size_t len;

    assert(w);
    assert(friend_number != UINT32_MAX);
    assert(cp);
    assert(IOEXcp_get_type(cp) == IOEXCP_TYPE_MESSAGE);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        vlogE("Carrier: Unknown friend number %lu, friend message dropped.",
              friend_number);
        return;
    }

    strcpy(friendid, fi->info.user_info.userid);
    deref(fi);

    name = IOEXcp_get_extension(cp);
    msg  = IOEXcp_get_raw_data(cp);
    len  = IOEXcp_get_raw_data_length(cp);

    if (!name) {
        if (w->callbacks.friend_message)
            w->callbacks.friend_message(w, friendid, msg, len, w->context);
    }
}

static
void handle_invite_request(IOEXCarrier *w, uint32_t friend_number, IOEXCP *cp)
{
    FriendInfo *fi;
    char friendid[IOEX_MAX_ID_LEN + 1];
    const char *name;
    const void *data;
    size_t len;
    int64_t tid;
    char from[IOEX_MAX_ID_LEN + IOEX_MAX_EXTENSION_NAME_LEN + 4];

    assert(w);
    assert(friend_number != UINT32_MAX);
    assert(cp);
    assert(IOEXcp_get_type(cp) == IOEXCP_TYPE_INVITE_REQUEST);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        vlogE("Carrier: Unknown friend number %lu, invite request dropped.",
              friend_number);
        return;
    }

    strcpy(friendid, fi->info.user_info.userid);
    deref(fi);

    name = IOEXcp_get_extension(cp);
    data = IOEXcp_get_raw_data(cp);
    len  = IOEXcp_get_raw_data_length(cp);
    tid  = IOEXcp_get_tid(cp);

    strcpy(from, friendid);
    if (name) {
        strcat(from, ":");
        strcat(from, name);
    }
    tansaction_history_put_invite(w->thistory, from, tid);

    if (name) {
        if (strcmp(name, "session") == 0) {
            SessionExtension *ext = (SessionExtension *)w->session;
            if (ext && ext->friend_invite_cb)
                ext->friend_invite_cb(w, friendid, data, len, ext);
        }
    } else {
        if (w->callbacks.friend_invite)
            w->callbacks.friend_invite(w, friendid, data, len, w->context);
    }
}

static
void handle_invite_response(IOEXCarrier *w, uint32_t friend_number, IOEXCP *cp)
{
    FriendInfo *fi;
    char friendid[IOEX_MAX_ID_LEN + 1];
    TransactedCallback *tcb;
    IOEXFriendInviteResponseCallback *callback_func;
    void *callback_ctxt;
    int64_t tid;
    int status;
    const char *reason = NULL;
    const void *data = NULL;
    size_t data_len = 0;

    assert(w);
    assert(friend_number != UINT32_MAX);
    assert(cp);
    assert(IOEXcp_get_type(cp) == IOEXCP_TYPE_INVITE_RESPONSE);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        vlogE("Carrier: Unknown friend number %lu, invite response dropped.",
              friend_number);
        return;
    }

    strcpy(friendid, fi->info.user_info.userid);
    deref(fi);

    tid = IOEXcp_get_tid(cp);
    tcb = transacted_callbacks_get(w->tcallbacks, tid);
    if (!tcb) {
        vlogE("Carrier: No transaction to handle invite response.");
        return;
    }

    callback_func = (IOEXFriendInviteResponseCallback *)tcb->callback_func;
    callback_ctxt = tcb->callback_context;
    assert(callback_func);

    deref(tcb);
    transacted_callbacks_remove(w->tcallbacks, tid);

    status = IOEXcp_get_status(cp);
    if (status) {
        reason = IOEXcp_get_reason(cp);
    } else {
        data = IOEXcp_get_raw_data(cp);
        data_len = IOEXcp_get_raw_data_length(cp);
    }

    callback_func(w, friendid, status, reason, data, data_len, callback_ctxt);
}

static
void notify_friend_message_cb(uint32_t friend_number, const uint8_t *message,
                              size_t length, void *context)
{
    IOEXCarrier *w = (IOEXCarrier *)context;
    IOEXCP *cp;

    cp = IOEXcp_decode(message, length);
    if (!cp) {
        vlogE("Carrier: Invalid DHT message, dropped.");
        return;
    }

    switch(IOEXcp_get_type(cp)) {
    case IOEXCP_TYPE_MESSAGE:
        handle_friend_message(w, friend_number, cp);
        break;
    case IOEXCP_TYPE_INVITE_REQUEST:
        handle_invite_request(w, friend_number, cp);
        break;
    case IOEXCP_TYPE_INVITE_RESPONSE:
        handle_invite_response(w, friend_number, cp);
        break;
    default:
        vlogE("Carrier: Unknown DHT message, dropped.");
        break;
    }

    IOEXcp_free(cp);
}

bool get_fullpath(const FileTracker *ft, char *fullpath)
{
    const IOEXFileInfo *info;

    if(!ft || !fullpath){
        return false;
    }

    info = &(ft->fi);
    if(info->file_path == NULL || strlen(info->file_path) == 0){
        snprintf(fullpath, IOEX_MAX_FULL_PATH_LEN, "%s", info->file_name);
    }
    else if(info->file_path[strlen(info->file_path)-1] == '/'){
        snprintf(fullpath, IOEX_MAX_FULL_PATH_LEN, "%s%s", info->file_path, info->file_name);
    }
    else {
        snprintf(fullpath, IOEX_MAX_FULL_PATH_LEN, "%s/%s", info->file_path, info->file_name);
    }
    return true;
}

bool is_sender(uint32_t file_number)
{
    return file_number < 65536;
}

FileTracker* _find_file_tracker(List *list, uint32_t friend_number, uint32_t file_number)
{
    if(!list)
        return NULL;

    ListIterator it;
    FileTracker *ft = NULL;
    IOEXFileInfo *info = NULL;
    int rc;

    list_iterate(list, &it);
    while(list_iterator_has_next(&it)){
        rc = list_iterator_next(&it, (void **)&ft);
        if(rc == 0){
            break;
        }
        info = &ft->fi;
        if(info->friend_number == friend_number && info->file_index == file_number){
            return ft;
        }
    }
    return NULL;
}

FileTracker* find_file_sender(IOEXCarrier *w, uint32_t friend_number, uint32_t file_number)
{
    return _find_file_tracker(w->file_senders, friend_number, file_number);
}

FileTracker* find_file_receiver(IOEXCarrier *w, uint32_t friend_number, uint32_t file_number)
{
    return _find_file_tracker(w->file_receivers, friend_number, file_number);
}

int add_new_file_sender(IOEXCarrier *w, uint32_t friend_number, uint32_t file_number, const char *fullpath)
{
    FileTracker *sender = (FileTracker *)rc_alloc(sizeof(FileTracker), NULL);
    if(sender == NULL){
        return IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY);
    }
    if(fullpath == NULL){
        return IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS);
    }

    char *pch = strrchr(fullpath, '/');
    if(pch == NULL){
        strncpy(sender->fi.file_name, fullpath, sizeof(sender->fi.file_name));
        strncpy(sender->fi.file_path, "", sizeof(sender->fi.file_path));
    }
    else{
        strncpy(sender->fi.file_name, pch+1, sizeof(sender->fi.file_name));
        strncpy(sender->fi.file_path, fullpath, pch-fullpath+1);
        sender->fi.file_path[pch-fullpath] = '\0';
    }
    sender->fi.friend_number = friend_number;
    sender->fi.file_index = file_number;
    sender->le.data = sender;

    list_add(w->file_senders, &sender->le);
    deref(sender);

    return IOEXSUCCESS;
}

int add_new_file_receiver(IOEXCarrier *w, uint32_t friend_number, uint32_t file_number, const char *filename)
{
    FileTracker *receiver = (FileTracker *)rc_alloc(sizeof(FileTracker), NULL);
    if(receiver == NULL){
        return IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY);
    }
    if(filename == NULL){
        return IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS);
    }

    strncpy(receiver->fi.file_name, filename, sizeof(receiver->fi.file_name));
    strncpy(receiver->fi.file_path, "/tmp/", sizeof(receiver->fi.file_path));
    receiver->fi.friend_number = friend_number;
    receiver->fi.file_index = file_number;
    receiver->le.data = receiver;

    list_add(w->file_receivers, &receiver->le);
    deref(receiver);

    return IOEXSUCCESS;
}

void remove_file_sender(IOEXCarrier *w, FileTracker *sender)
{
    deref(list_remove_entry(w->file_senders, &sender->le));
}

void remove_file_receiver(IOEXCarrier *w, FileTracker *receiver)
{
    deref(list_remove_entry(w->file_receivers, &receiver->le));
}

int update_file_receiver_path(FileTracker *receiver, const char *filename, const char *filepath)
{
    if(receiver == NULL){
        return IOEX_GENERAL_ERROR(IOEXERR_FILE_TRACKER_INVALID);
    }

    IOEXFileInfo *info = &receiver->fi;
    strncpy(info->file_name, filename, IOEX_MAX_FILE_NAME_LEN);
    strncpy(info->file_path, filepath, IOEX_MAX_FILE_PATH_LEN);

    return IOEXSUCCESS;
}

static 
void notify_file_request_cb(uint32_t friend_number, uint32_t file_number, 
                            const uint8_t *filename, uint64_t filesize, void *context)
{
    IOEXCarrier *w = (IOEXCarrier *)context;
    FriendInfo *fi;
    int rc;

    assert(friend_number != UINT32_MAX);
    assert(filename);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        vlogE("Carrier: Unknown friend number %lu, file request of %s, index %u dropped.", friend_number, filename, file_number);
        return;
    }

    rc = add_new_file_receiver(w, friend_number, file_number, (char *)filename);
    if(rc < 0){
        IOEX_set_error(rc);
        vlogE("Carrier: cannot add file receiver for friend_number:%u, file_number:%u (0x%08X)", friend_number, file_number, rc);
        return;
    }

    if(w->callbacks.file_request){
        w->callbacks.file_request(w, fi->info.user_info.userid, file_number, (char *)filename, filesize, w->context);
    }
}

static
void notify_file_accepted_cb(const uint32_t friend_number, const uint32_t file_number, 
                             void *context)
{
    IOEXCarrier *w = (IOEXCarrier *)context;
    FriendInfo *fi;

    assert(friend_number != UINT32_MAX);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        vlogE("Carrier: Unknown friend number %lu, file accepted control index %u dropped.", friend_number, file_number);
        return;
    }

    if(!find_file_sender(w, friend_number, file_number)){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_FILE_TRACKER_INVALID));
        vlogE("Carrier: cannot find file sender for friend_number:%u file_number:%u", friend_number, file_number);
        return;
    }

    if(w->callbacks.file_accepted){
        w->callbacks.file_accepted(w, fi->info.user_info.userid, file_number, w->context);
    }
}

static
void notify_file_rejected_cb(const uint32_t friend_number, const uint32_t file_number, 
                             void *context)
{
    IOEXCarrier *w = (IOEXCarrier *)context;
    FriendInfo *fi;

    assert(friend_number != UINT32_MAX);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        vlogE("Carrier: Unknown friend number %lu, file rejected control index %u dropped.", friend_number, file_number);
        return;
    }

    FileTracker *sender = NULL;
    if((sender = find_file_sender(w, friend_number, file_number))==NULL){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_FILE_TRACKER_INVALID));
        vlogE("Carrier: Cannot remove file sender with friend_number:%u file_number:%u", friend_number, file_number);
        return;
    }
    remove_file_sender(w, sender);

    if(w->callbacks.file_rejected){
        w->callbacks.file_rejected(w, fi->info.user_info.userid, file_number, w->context);
    }
}

static
void notify_file_paused_cb(const uint32_t friend_number, const uint32_t file_number, 
                            void *context)
{
    IOEXCarrier *w = (IOEXCarrier *)context;
    FriendInfo *fi;

    assert(friend_number != UINT32_MAX);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        vlogE("Carrier: Unknown friend number %lu, file paused control index %u dropped.", friend_number, file_number);
        return;
    }

    FileTracker *tracker = NULL;
    if(is_sender(file_number)){
        tracker = find_file_sender(w, friend_number, file_number);
    }
    else {
        tracker = find_file_receiver(w, friend_number, file_number);
    }
    if(tracker == NULL){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_FILE_TRACKER_INVALID));
        vlogE("Carrier: cannot find file tracker for friend_number:%u file_number:%u", friend_number, file_number);
        return;
    }

    if(w->callbacks.file_paused){
        w->callbacks.file_paused(w, fi->info.user_info.userid, file_number, w->context);
    }
}

static
void notify_file_resumed_cb(const uint32_t friend_number, const uint32_t file_number, 
                            void *context)
{
    IOEXCarrier *w = (IOEXCarrier *)context;
    FriendInfo *fi;

    assert(friend_number != UINT32_MAX);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        vlogE("Carrier: Unknown friend number %lu, file resumed control index %u dropped.", friend_number, file_number);
        return;
    }

    FileTracker *tracker = NULL;
    if(is_sender(file_number)){
        tracker = find_file_sender(w, friend_number, file_number);
    }
    else {
        tracker = find_file_receiver(w, friend_number, file_number);
    }
    if(tracker == NULL){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_FILE_TRACKER_INVALID));
        vlogE("Carrier: cannot find file tracker for friend_number:%u file_number:%u", friend_number, file_number);
        return;
    }

    if(w->callbacks.file_resumed){
        w->callbacks.file_resumed(w, fi->info.user_info.userid, file_number, w->context);
    }
}

static
void notify_file_canceled_cb(const uint32_t friend_number, const uint32_t file_number, 
                             void *context)
{
    IOEXCarrier *w = (IOEXCarrier *)context;
    FriendInfo *fi;
    char fullpath[IOEX_MAX_FULL_PATH_LEN + 1];

    assert(friend_number != UINT32_MAX);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        vlogE("Carrier: Unknown friend number %lu, file canceled control index %u dropped.", friend_number, file_number);
        return;
    }

    FileTracker *tracker = NULL;
    if(is_sender(file_number)){
        tracker = find_file_sender(w, friend_number, file_number);
        remove_file_sender(w, tracker);
    }
    else {
        // Receiver side should remove the partially completed file
        tracker = find_file_receiver(w, friend_number, file_number);
        if(get_fullpath(tracker, fullpath)){
            unlink(fullpath);
        }
        remove_file_receiver(w, tracker);
    }
    
    if(w->callbacks.file_canceled){
        w->callbacks.file_canceled(w, fi->info.user_info.userid, file_number, w->context);
    }
}

static 
void notify_file_chunk_request_cb(const uint32_t friend_number, const uint32_t file_number, const uint64_t position,
                                  const size_t length, void *context)
{
    IOEXCarrier *w = (IOEXCarrier *)context;
    FriendInfo *fi;
    char tmpid[IOEX_MAX_ID_LEN + 1];
    int rc;

    assert(friend_number != UINT32_MAX);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        vlogE("Carrier: Unknown friend number %lu, file chunk request for %u dropped.", friend_number, file_number);
        return;
    }
    strcpy(tmpid, fi->info.user_info.userid);

    // TODO: use file sender structure to set the event, and do the transimitting in main loop
    //       don't just send the chunk in this callback

    FILE *fp = NULL;
    char fullpath[IOEX_MAX_FULL_PATH_LEN + 1];
    FileTracker *sender;
    if((sender = find_file_sender(w, friend_number, file_number)) != NULL){
        if(length == 0){
            remove_file_sender(w, sender);
        }
        else if(get_fullpath(sender, fullpath)){
            fp = fopen(fullpath, "rb");
        }
    }

    if(length > 0){
        if(fp != NULL){
            fseek(fp, position, SEEK_SET);
            uint8_t data[4096];
            int len = fread(data, 1, length, fp);
            rc = dht_file_send_chunk(&w->dht, friend_number, file_number, position, data, len);
            fclose(fp);
            if(rc < 0 && w->callbacks.file_chunk_send_error){
                w->callbacks.file_chunk_send_error(w, rc, tmpid, file_number, fullpath, position, length, w->context);
            }
            else if( w->callbacks.file_chunk_send){
                w->callbacks.file_chunk_send(w, tmpid, file_number, fullpath, position, length, w->context);
            }
        }
        else {
            vlogE("Cannot respond to the file[%s] chunk request", fullpath);
            if(w->callbacks.file_chunk_send_error){
                w->callbacks.file_chunk_send_error(w, IOEX_GENERAL_ERROR(IOEXERR_FILE_INVALID), tmpid, file_number,
                                                   fullpath, position, length, w->context);
            }
        }
    }
}

static
void notify_file_chunk_receive_cb(uint32_t friend_number, uint32_t file_number, uint64_t position, const uint8_t *data,
                                  size_t length, void *context)
{
    IOEXCarrier *w = (IOEXCarrier *)context;
    FriendInfo *fi;
    char tmpid[IOEX_MAX_ID_LEN + 1];

    assert(friend_number != UINT32_MAX);

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        vlogE("Carrier: Unknown friend number %lu, file chunk request for %u dropped.", friend_number, file_number);
        return;
    }
    strcpy(tmpid, fi->info.user_info.userid);

    // TODO: use file sender structure to set the event, and do the transimitting in main loop
    //       don't just send the chunk in this callback

    FileTracker *receiver;
    FILE *fp = NULL;
    char fullpath[IOEX_MAX_FULL_PATH_LEN + 1];
    if((receiver = find_file_receiver(w, friend_number, file_number)) != NULL){
        if(length == 0){
            remove_file_receiver(w, receiver);
        }
        else if(get_fullpath(receiver, fullpath)){
            fp = fopen(fullpath, "ab");
        }
    }

    if(length > 0){
        if(fp != NULL){
            fseek(fp, position, SEEK_SET);
            fwrite(data, length, 1, fp);
            fclose(fp);
        }
        else {
            vlogE("Cannot write file chunk to the file[%s]", fullpath);
        }
    }
    else{
        vlogI("File[%s] receive complete.", fullpath);
    }

    if(w->callbacks.file_chunk_receive){
        w->callbacks.file_chunk_receive(w, tmpid, file_number, fullpath, position, length, w->context);
    }
}

static void connect_to_bootstraps(IOEXCarrier *w)
{
    int i;

    for (i = 0; i < w->pref.bootstraps_size; i++) {
        BootstrapNodeBuf *bi = &w->pref.bootstraps[i];
        char id[IOEX_MAX_ID_LEN + 1] = {0};
        size_t id_len = sizeof(id);
        int rc;

        base58_encode(bi->public_key, DHT_PUBLIC_KEY_SIZE, id, &id_len);
        rc = dht_bootstrap(&w->dht, bi->ipv4, bi->ipv6, bi->port, bi->public_key);
        if (rc < 0) {
            vlogW("Carrier: Try to connect to bootstrap "
                  "[ipv4:%s, ipv6:%s, port:%d, public_key:%s] error.",
                  *bi->ipv4 ? bi->ipv4 : "N/A", *bi->ipv6 ? bi->ipv6 : "N/A",
                  bi->port, id);
        } else {
            vlogT("Carrier: Try to connect to bootstrap "
                  "[ipv4:%s, ipv6:%s, port:%d, public_key:%s] succeess.",
                  *bi->ipv4 ? bi->ipv4 : "N/A", *bi->ipv6 ? bi->ipv6 : "N/A",
                  bi->port, id);
        }
    }
}

int IOEX_run(IOEXCarrier *w, int interval)
{
    if (!w || interval < 0) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (interval == 0)
        interval = 1000; // in milliseconds.

    ref(w);

    w->dht_callbacks.notify_connection = notify_connection_cb;
    w->dht_callbacks.notify_friend_desc = notify_friend_description_cb;
    w->dht_callbacks.notify_friend_connection = notify_friend_connection_cb;
    w->dht_callbacks.notify_friend_status = notify_friend_status_cb;
    w->dht_callbacks.notify_friend_request = notify_friend_request_cb;
    w->dht_callbacks.notify_friend_message = notify_friend_message_cb;

    w->dht_callbacks.notify_file_request = notify_file_request_cb;
    w->dht_callbacks.notify_file_accepted = notify_file_accepted_cb;
    w->dht_callbacks.notify_file_rejected = notify_file_rejected_cb;
    w->dht_callbacks.notify_file_paused = notify_file_paused_cb;
    w->dht_callbacks.notify_file_resumed = notify_file_resumed_cb;
    w->dht_callbacks.notify_file_canceled = notify_file_canceled_cb;
    w->dht_callbacks.notify_file_chunk_request = notify_file_chunk_request_cb;
    w->dht_callbacks.notify_file_chunk_receive = notify_file_chunk_receive_cb;

    w->dht_callbacks.context = w;

    notify_friends(w);

    w->running = 1;

    connect_to_bootstraps(w);

    while(!w->quit) {
        int idle_interval;
        struct timeval expire;
        struct timeval check;
        struct timeval tmp;

        gettimeofday(&expire, NULL);

        idle_interval = dht_iteration_idle(&w->dht);
        if (idle_interval > interval)
            idle_interval = interval;

        tmp.tv_sec = 0;
        tmp.tv_usec = idle_interval * 1000;

        timeradd(&expire, &tmp, &expire);

        do_friend_events(w);

        if (idle_interval > 0)
            notify_idle(w);

        // TODO: Check connection:.

        gettimeofday(&check, NULL);

        if (timercmp(&expire, &check, >)) {
            timersub(&expire, &check, &tmp);
            usleep(tmp.tv_usec);
        }

        dht_iterate(&w->dht, &w->dht_callbacks);
    }

    w->running = 0;

    store_persistence_data(w);

    deref(w);

    return 0;
}

char *IOEX_get_address(IOEXCarrier *w, char *address, size_t length)
{
    if (!w || !address || !length) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return NULL;
    }

    if (strlen(w->base58_addr) >= length) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_BUFFER_TOO_SMALL));
        return NULL;
    }

    strcpy(address, w->base58_addr);
    return address;
}

char *IOEX_get_nodeid(IOEXCarrier *w, char *nodeid, size_t len)
{
    if (!w || !nodeid || !len) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return NULL;
    }

    if (strlen(w->me.userid) >= len) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_BUFFER_TOO_SMALL));
        return NULL;
    }

    strcpy(nodeid, w->me.userid);
    return nodeid;
}

char *IOEX_get_userid(IOEXCarrier *w, char *userid, size_t len)
{
    return IOEX_get_nodeid(w, userid, len);
}

int IOEX_set_self_nospam(IOEXCarrier *w, uint32_t nospam)
{
    int rc;

    if (!w) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    dht_self_set_nospam(&w->dht, nospam);

    rc = dht_get_self_info(&w->dht, get_self_info_cb, w);
    if (rc < 0) {
        IOEX_set_error(rc);
        return -1;
    }

    store_persistence_data(w);

    return 0;
}

int IOEX_get_self_nospam(IOEXCarrier *w, uint32_t *nospam)
{
    if (!w || !nospam) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    *nospam = dht_self_get_nospam(&w->dht);

    return 0;
}

int IOEX_set_self_info(IOEXCarrier *w, const IOEXUserInfo *info)
{
    IOEXCP *cp;
    uint8_t *data;
    size_t data_len;
    bool did_changed = false;

    if (!w || !info) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (strcmp(info->userid, w->me.userid) != 0) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    cp = IOEXcp_create(IOEXCP_TYPE_USERINFO, NULL);
    if (!cp) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return -1;
    }

    if (info->has_avatar != w->me.has_avatar ||
        strcmp(info->name, w->me.name) ||
        strcmp(info->description, w->me.description) ||
        strcmp(info->gender, w->me.gender) ||
        strcmp(info->phone, w->me.phone) ||
        strcmp(info->email, w->me.email) ||
        strcmp(info->region, w->me.region)) {
        did_changed = true;
    } else {
        IOEXcp_free(cp);
    }

    if (did_changed) {
        IOEXcp_set_has_avatar(cp, !!info->has_avatar);
        IOEXcp_set_name(cp, info->name);
        IOEXcp_set_descr(cp, info->description);
        IOEXcp_set_gender(cp, info->gender);
        IOEXcp_set_phone(cp, info->phone);
        IOEXcp_set_email(cp, info->email);
        IOEXcp_set_region(cp, info->region);

        data = IOEXcp_encode(cp, &data_len);
        IOEXcp_free(cp);

        if (!data) {
            IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
            return -1;
        }

        /* Use tox status message as user information. The total length of
           user information is about 700, far less than the max length
           value of status message (1007).
         */
        w->me.has_avatar = info->has_avatar;
        strcpy(w->me.name, info->name);
        strcpy(w->me.description, info->description);
        strcpy(w->me.gender, info->gender);
        strcpy(w->me.phone, info->phone);
        strcpy(w->me.email, info->email);
        strcpy(w->me.region, info->region);
        dht_self_set_desc(&w->dht, data, data_len);

        store_persistence_data(w);

        free(data);
    }

    return 0;
}

int IOEX_get_self_info(IOEXCarrier *w, IOEXUserInfo *info)
{
    if (!w || !info) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    memcpy(info, &w->me, sizeof(IOEXUserInfo));

    return 0;
}

int IOEX_set_self_presence(IOEXCarrier *w, IOEXPresenceStatus status)
{
    if (!w) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (status < IOEXPresenceStatus_None ||
        status > IOEXPresenceStatus_Busy) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    dht_self_set_status(&w->dht, (int)status);

    return 0;
}

int IOEX_get_self_presence(IOEXCarrier *w, IOEXPresenceStatus *status)
{
    int presence_status;

    if (!w || !status) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    presence_status = dht_self_get_status(&w->dht);

    if (presence_status < IOEXPresenceStatus_None)
        *status = IOEXPresenceStatus_None;
    else if (presence_status > IOEXPresenceStatus_Busy)
        *status = IOEXPresenceStatus_None;
    else
        *status = (IOEXPresenceStatus)presence_status;

    return 0;
}

bool IOEX_is_ready(IOEXCarrier *w)
{
    if (!w) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return false;
    }

    return w->is_ready;
}

int IOEX_get_friends(IOEXCarrier *w,
                    IOEXFriendsIterateCallback *callback, void *context)
{
    HashtableIterator it;

    if (!w || !callback) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    friends_iterate(w->friends, &it);
    while(friends_iterator_has_next(&it)) {
        FriendInfo *fi;

        if (friends_iterator_next(&it, &fi) == 1) {
            IOEXFriendInfo wfi;

            memcpy(&wfi, &fi->info, sizeof(IOEXFriendInfo));
            deref(fi);

            if (!callback(&wfi, context))
                return 0;
        }
    }

    /* Friend list is end */
    callback(NULL, context);

    return 0;
}

int IOEX_get_friend_info(IOEXCarrier *w, const char *friendid,
                        IOEXFriendInfo *info)
{
    uint32_t friend_number;
    FriendInfo *fi;
    int rc;

    if (!w || !friendid || !info) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    rc = get_friend_number(w, friendid, &friend_number);
    if (rc < 0) {
        IOEX_set_error(rc);
        return -1;
    }

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }
    assert(!strcmp(friendid, fi->info.user_info.userid));

    memcpy(info, &fi->info, sizeof(IOEXFriendInfo));

    deref(fi);

    return 0;
}

int IOEX_set_friend_label(IOEXCarrier *w,
                             const char *friendid, const char *label)
{
    uint32_t friend_number;
    FriendInfo *fi;
    int rc;

    if (!w || !friendid) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (label && strlen(label) > IOEX_MAX_USER_NAME_LEN) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    rc = get_friend_number(w, friendid, &friend_number);
    if (rc < 0) {
        IOEX_set_error(rc);
        return -1;
    }

    fi = friends_get(w->friends, friend_number);
    if (!fi) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }
    assert(!strcmp(friendid, fi->info.user_info.userid));

    strcpy(fi->info.label, label ? label : "");

    deref(fi);

    store_persistence_data(w);

    return 0;
}

bool IOEX_is_friend(IOEXCarrier *w, const char *userid)
{
    uint32_t friend_number;
    int rc;

    if (!w || !userid) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return false;
    }

    rc = get_friend_number(w, userid, &friend_number);
    if (rc < 0 || friend_number == UINT32_MAX) {
        IOEX_set_error(rc);
        return false;
    }

    return !!friends_exist(w->friends, friend_number);
}

int IOEX_add_friend(IOEXCarrier *w, const char *address, const char *hello)
{
    uint32_t friend_number;
    FriendInfo *fi;
    uint8_t addr[DHT_ADDRESS_SIZE];
    IOEXCP *cp;
    uint8_t *data;
    size_t data_len;
    size_t _len;
    int rc;

    if (!w || !hello || !address) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (!is_valid_address(address)) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (!strcmp(address, w->base58_addr)) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_READY));
        return -1;
    }

    base58_decode(address, strlen(address), addr, sizeof(addr));

    rc = dht_get_friend_number(&w->dht, addr, &friend_number);
    if (rc == 0 && friend_number != UINT32_MAX) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_ALREADY_EXIST));
        return -1;
    }

    fi = (FriendInfo *)rc_zalloc(sizeof(FriendInfo), NULL);
    if (!fi) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return -1;
    }

    cp = IOEXcp_create(IOEXCP_TYPE_FRIEND_REQUEST, NULL);
    if (!cp) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        deref(fi);
        return -1;
    }

    IOEXcp_set_name(cp, w->me.name);
    IOEXcp_set_descr(cp, w->me.description);
    IOEXcp_set_hello(cp, hello);

    data = IOEXcp_encode(cp, &data_len);
    IOEXcp_free(cp);

    if (!data) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        deref(fi);
        return -1;
    }

    rc = dht_friend_add(&w->dht, addr, data, data_len, &friend_number);
    free(data);

    if (rc < 0) {
        IOEX_set_error(rc);
        deref(fi);
        return -1;
    }

    _len = sizeof(fi->info.user_info.userid);
    base58_encode(addr, DHT_PUBLIC_KEY_SIZE, fi->info.user_info.userid, &_len);

    fi->friend_number = friend_number;
    fi->info.presence = IOEXPresenceStatus_None;
    fi->info.status   = IOEXConnectionStatus_Disconnected;
    friends_put(w->friends, fi);

    notify_friend_added(w, &fi->info);

    deref(fi);

    return 0;
}

int IOEX_accept_friend(IOEXCarrier *w, const char *userid)
{
    uint32_t friend_number = UINT32_MAX;
    uint8_t public_key[DHT_PUBLIC_KEY_SIZE];
    FriendInfo *fi;
    int rc;

    if (!w || !userid) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (!is_valid_key(userid)) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (strcmp(userid, w->me.userid) == 0) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_READY));
        return -1;
    }

    rc = get_friend_number(w, userid, &friend_number);
    if (rc == 0 && friend_number != UINT32_MAX) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_ALREADY_EXIST));
        return -1;
    }

    fi = (FriendInfo *)rc_zalloc(sizeof(FriendInfo), NULL);
    if (!fi) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return -1;
    }

    base58_decode(userid, strlen(userid), public_key, sizeof(public_key));
    rc = dht_friend_add_norequest(&w->dht, public_key, &friend_number);
    if (rc < 0) {
        deref(fi);
        IOEX_set_error(rc);
        return -1;
    }

    strcpy(fi->info.user_info.userid, userid);

    fi->friend_number = friend_number;
    fi->info.presence = IOEXPresenceStatus_None;
    fi->info.status   = IOEXConnectionStatus_Disconnected;

    friends_put(w->friends, fi);

    notify_friend_added(w, &fi->info);

    deref(fi);

    return 0;
}

int IOEX_remove_friend(IOEXCarrier *w, const char *friendid)
{
    uint32_t friend_number;
    FriendInfo *fi;
    int rc;

    if (!w || !friendid) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (!is_valid_key(friendid)) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_READY));
        return -1;
    }

    rc = get_friend_number(w, friendid, &friend_number);
    if (rc < 0) {
        IOEX_set_error(rc);
        return -1;
    }

    if (!friends_exist(w->friends, friend_number)) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    dht_friend_delete(&w->dht, friend_number);

    fi = friends_remove(w->friends, friend_number);
    assert(fi);

    notify_friend_removed(w, &fi->info);

    deref(fi);

    return 0;
}

static void parse_address(const char *addr, char **uid, char **ext)
{
    char *colon_pos = NULL;

    assert(addr);
    assert(uid && ext);

    /* address format: userid:extenison */
    if (uid)
        *uid = (char *)addr;

    colon_pos = strchr(addr, ':');
    if (colon_pos) {
        if (ext)
            *ext = colon_pos+1;
        *colon_pos = 0;
    } else {
        if (ext)
            *ext = NULL;
    }
}

int IOEX_send_friend_message(IOEXCarrier *w, const char *to, const void *msg,
                            size_t len)
{
    char *addr, *userid, *ext_name;
    uint32_t friend_number;
    int rc;
    IOEXCP *cp;
    uint8_t *data;
    size_t data_len;

    if (!w || !to || !msg || !len || len > IOEX_MAX_APP_MESSAGE_LEN) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    addr = alloca(strlen(to) + 1);
    strcpy(addr, to);
    parse_address(addr, &userid, &ext_name);

    if (!is_valid_key(userid)) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (ext_name && strlen(ext_name) > IOEX_MAX_USER_NAME_LEN) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (strcmp(userid, w->me.userid) == 0) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        vlogE("Carrier: Send message to myself not allowed.");
        return -1;
    }

    if (!w->is_ready) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_READY));
        return -1;
    }

    rc = get_friend_number(w, userid, &friend_number);
    if (rc < 0) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    if (!friends_exist(w->friends, friend_number)) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    cp = IOEXcp_create(IOEXCP_TYPE_MESSAGE, ext_name);
    if (!cp) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return -1;
    }

    IOEXcp_set_raw_data(cp, msg, len);

    data = IOEXcp_encode(cp, &data_len);
    IOEXcp_free(cp);

    if (!data) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return -1;
    }

    rc = dht_friend_message(&w->dht, friend_number, data, data_len);
    free(data);

    if (rc < 0) {
        IOEX_set_error(rc);
        return -1;
    }

    return 0;
}

static int64_t generate_tid(void)
{
    int64_t tid;

    do {
        tid = time(NULL);
        tid += rand();
    } while (tid == 0);

    return tid;
}

int IOEX_invite_friend(IOEXCarrier *w, const char *to,
                      const void *data, size_t len,
                      IOEXFriendInviteResponseCallback *callback,
                      void *context)
{
    char *addr, *userid, *ext_name;
    uint32_t friend_number;
    IOEXCP *cp;
    int rc;
    TransactedCallback *tcb;
    int64_t tid;
    uint8_t *_data;
    size_t _data_len;

    if (!w || !to || !data || !len || !callback) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    addr = alloca(strlen(to) + 1);
    strcpy(addr, to);
    parse_address(addr, &userid, &ext_name);

    if (!is_valid_key(userid)) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (ext_name && strlen(ext_name) > IOEX_MAX_USER_NAME_LEN) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_READY));
        return -1;
    }

    rc = get_friend_number(w, userid, &friend_number);
    if (rc < 0) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    if (!friends_exist(w->friends, friend_number)) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    cp = IOEXcp_create(IOEXCP_TYPE_INVITE_REQUEST, ext_name);
    if (!cp) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return -1;
    }

    tid = generate_tid();

    IOEXcp_set_tid(cp, &tid);
    IOEXcp_set_raw_data(cp, data, len);

    _data = IOEXcp_encode(cp, &_data_len);
    IOEXcp_free(cp);

    if (!_data) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return -1;
    }

    tcb = (TransactedCallback*)rc_alloc(sizeof(TransactedCallback), NULL);
    if (!tcb) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        free(_data);
        return -1;
    }

    tcb->tid = tid;
    tcb->callback_func = callback;
    tcb->callback_context = context;

    transacted_callbacks_put(w->tcallbacks, tcb);
    deref(tcb);

    rc = dht_friend_message(&w->dht, friend_number, _data, _data_len);
    free(_data);

    if (rc < 0) {
        IOEX_set_error(rc);
        return -1;
    }

    return 0;
}

int IOEX_reply_friend_invite(IOEXCarrier *w, const char *to,
                                int status, const char *reason,
                                const void *data, size_t len)
{
    char *addr, *userid, *ext_name;
    uint32_t friend_number;
    int64_t tid;
    IOEXCP *cp;
    int rc;
    uint8_t *_data;
    size_t _data_len;

    if (!w || !to || !*to || (status != 0 && !reason)
            || (status == 0 && (!data || !len))) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    addr = alloca(strlen(to) + 1);
    strcpy(addr, to);
    parse_address(addr, &userid, &ext_name);

    if (!is_valid_key(userid)) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (ext_name && strlen(ext_name) > IOEX_MAX_USER_NAME_LEN) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (!w->is_ready) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_READY));
        return -1;
    }

    rc = get_friend_number(w, userid, &friend_number);
    if (rc < 0) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    if (!friends_exist(w->friends, friend_number)) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
        return -1;
    }

    tid = transaction_history_get_invite(w->thistory, to);
    if (tid == 0) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NO_MATCHED_REQUEST));
        return -1;
    }

    cp = IOEXcp_create(IOEXCP_TYPE_INVITE_RESPONSE, ext_name);
    if (!cp) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return -1;
    }

    IOEXcp_set_tid(cp, &tid);
    IOEXcp_set_status(cp, status);
    if (status)
        IOEXcp_set_reason(cp, reason);
    else
        IOEXcp_set_raw_data(cp, data, len);

    _data = IOEXcp_encode(cp, &_data_len);
    IOEXcp_free(cp);

    if (!_data) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_OUT_OF_MEMORY));
        return -1;
    }

    rc = dht_friend_message(&w->dht, friend_number, _data, _data_len);
    free(_data);

    if (rc < 0) {
        IOEX_set_error(rc);
        return -1;
    }

    transaction_history_remove_invite(w->thistory, to);

    return 0;
}

int IOEX_get_turn_server(IOEXCarrier *w, IOEXTurnServer *turn_server)
{
    uint8_t secret_key[PUBLIC_KEY_BYTES];
    uint8_t public_key[PUBLIC_KEY_BYTES];
    uint8_t shared_key[SYMMETRIC_KEY_BYTES];
    uint8_t nonce[NONCE_BYTES];
    uint8_t digest[SHA256_BYTES];
    char nonce_str[64];
    size_t text_len;
    int rc;
    int times = 0;

    if (!w || !turn_server) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

redo_get_tcp_relay:
    rc = dht_get_random_tcp_relay(&w->dht, turn_server->server,
                                  sizeof(turn_server->server), public_key);
    if (rc < 0) {
        if (++times < 5) {
            usleep(1000);
            //BUGBUG: Try to get tcp relay again and again.
            goto redo_get_tcp_relay;
        } else {
            vlogE("Carrier: Get turn server address and public key error (%d)", rc);
            IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_EXIST));
            return -1;
        }
    }

    {
        char bootstrap_pk[IOEX_MAX_ID_LEN + 1];
        size_t pk_len = sizeof(bootstrap_pk);

        base58_encode(public_key, sizeof(public_key), bootstrap_pk, &pk_len);
        vlogD("Carrier: Acquired a random tcp relay (ip: %s, pk: %s)",
              turn_server->server, bootstrap_pk);
    }

    turn_server->port = TURN_SERVER_PORT;

    dht_self_get_secret_key(&w->dht, secret_key);
    crypto_compute_symmetric_key(public_key, secret_key, shared_key);

    crypto_random_nonce(nonce);
    rc = (int)hmac_sha256(shared_key, sizeof(shared_key),
                          nonce, sizeof(nonce), digest, sizeof(digest));

    memset(secret_key, 0, sizeof(secret_key));
    memset(shared_key, 0, sizeof(shared_key));

    if (rc != sizeof(digest)) {
        vlogE("Carrier: Hmac sha256 to nonce error");
        return -1;
    }

    text_len = sizeof(turn_server->password);
    base58_encode(digest, sizeof(digest), turn_server->password, &text_len);

    text_len = sizeof(nonce_str);
    base58_encode(nonce, sizeof(nonce), nonce_str, &text_len);

    sprintf(turn_server->username, "%s@%s.%s", w->me.userid, nonce_str, TURN_SERVER_USER_SUFFIX);

    strcpy(turn_server->realm, TURN_REALM);

    vlogD("Carrier: Valid turn server information: >>>>");
    vlogD("    host: %s", turn_server->server);
    vlogD("    port: %hu", turn_server->port);
    vlogD("   realm: %s", turn_server->realm);
    vlogD("username: %s", turn_server->username);
    vlogD("password: %s", turn_server->password);
    vlogD("<<<<");

    return 0;
}

bool is_file_exist(const char *fullpath){
    FILE *fp = fopen(fullpath, "rb");
    if(fp == NULL){
        return false;
    }
    fclose(fp);
    return true;
}

bool is_file_writable(const char *fullpath){
    FILE *fp = fopen(fullpath, "ab");
    if(fp == NULL){
        return false;
    }
    fclose(fp);
    return true;
}

int IOEX_get_files(IOEXCarrier *w, IOEXFilesIterateCallback *callback, void *context)
{
    ListIterator it;
    int rc;

    if (!w || !callback) {
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }

    list_iterate(w->file_senders, &it);
    while(list_iterator_has_next(&it)) {
        FileTracker *ft;

        rc = list_iterator_next(&it, (void **)&ft);
        if (rc == 0)
            break;

        IOEXFileInfo wfi;

        memcpy(&wfi, &ft->fi, sizeof(IOEXFileInfo));
        deref(ft);

        if (!callback(0, &wfi, context))
            return 0;
    }
    list_iterate(w->file_receivers, &it);
    while(list_iterator_has_next(&it)) {
        FileTracker *ft;

        rc = list_iterator_next(&it, (void **)&ft);
        if (rc == 0)
            break;

        IOEXFileInfo wfi;

        memcpy(&wfi, &ft->fi, sizeof(IOEXFileInfo));
        deref(ft);

        if (!callback(1, &wfi, context))
            return 0;
    }

    /* File list is end */
    callback(0, NULL, context);

    return 0;
}

int IOEX_send_file_request(IOEXCarrier *w, const char *friendid, const char *fullpath)
{
    uint32_t friend_number;
    uint32_t file_number = UINT32_MAX;

    int rc;
    if(!w || !friendid || !fullpath){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }
    if(!is_valid_key(friendid)){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }
    if(!w->is_ready){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_READY));
        return -1;
    }    

    rc = get_friend_number(w, friendid, &friend_number);
    if(rc < 0){
        IOEX_set_error(rc);
        return -1;
    }

    rc = dht_file_send_request(&w->dht, friend_number, fullpath, &file_number);
    if(rc < 0 || file_number == UINT32_MAX){
        IOEX_set_error(rc);
        return -1;
    }

    rc = add_new_file_sender(w, friend_number, file_number, fullpath);
    if(rc < 0){
        IOEX_set_error(rc);
        return -1;
    }

    return 0;
}

int IOEX_send_file_seek(IOEXCarrier *w, const char *friendid, const char *fileindex, const char *position)
{
    uint32_t friend_number;
    uint32_t file_number;
    uint64_t start_position;
    int rc;

    if(!w || !friendid || !fileindex || !position){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }
    if(!is_valid_key(friendid)){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }
    if(!w->is_ready){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_READY));
        return -1;
    }

    rc = get_friend_number(w, friendid, &friend_number);
    if(rc < 0){
        IOEX_set_error(rc);
        return -1;
    }

    FileTracker *receiver;
    file_number = strtoul(fileindex, NULL, 10);
    if((receiver = find_file_receiver(w, friend_number, file_number)) == NULL){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_FILE_INVALID));
        return -1;
    }

    start_position = strtoull(position, NULL, 10);
    rc = dht_file_send_seek(&w->dht, friend_number, file_number, start_position);
    if(rc < 0){
        IOEX_set_error(rc);
        return -1;
    }

    return 0;
}

int IOEX_send_file_accept(IOEXCarrier *w, const char *friendid, const char *fileindex, const char *filename, const char *filepath)
{
    uint32_t friend_number;
    uint32_t file_number;
    char fullpath[IOEX_MAX_FULL_PATH_LEN + 1];
    int rc;

    if(!w || !friendid || !fileindex || !filename || !filepath){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }
    if(!is_valid_key(friendid)){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }
    if(!w->is_ready){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_READY));
        return -1;
    }
    
    rc = get_friend_number(w, friendid, &friend_number);
    if(rc < 0){
        IOEX_set_error(rc);
        return -1;
    }

    if(filepath[strlen(filepath)-1]=='/'){
        snprintf(fullpath, sizeof(fullpath), "%s%s", filepath, filename);
    }
    else{
        snprintf(fullpath, sizeof(fullpath), "%s/%s", filepath, filename);
    }

    if(!is_file_writable(fullpath)){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_FILE_DENY));
        return -1;
    }

    file_number = strtoul(fileindex, NULL, 10);
    FileTracker *receiver = NULL;
    if((receiver = find_file_receiver(w, friend_number, file_number)) == NULL){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_FILE_TRACKER_INVALID));
        return -1;
    }

    rc = update_file_receiver_path(receiver, filename, filepath);
    if(rc < 0){
        IOEX_set_error(rc);
        return -1;
    }

    rc = dht_file_send_accept(&w->dht, friend_number, file_number);
    if(rc < 0){
        IOEX_set_error(rc);
        return -1;
    }

    return 0;
}

int IOEX_send_file_reject(IOEXCarrier *w, const char *friendid, const char *fileindex)
{
    uint32_t friend_number;
    uint32_t file_number;
    int rc;

    if(!w || !friendid || !fileindex){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }
    if(!is_valid_key(friendid)){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }
    if(!w->is_ready){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_READY));
        return -1;
    }
    
    rc = get_friend_number(w, friendid, &friend_number);
    if(rc < 0){
        IOEX_set_error(rc);
        return -1;
    }

    FileTracker *receiver = NULL;
    file_number = strtoul(fileindex, NULL, 10);
    if((receiver = find_file_receiver(w, friend_number, file_number)) == NULL){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_FILE_TRACKER_INVALID));
        return -1;
    }

    remove_file_receiver(w, receiver);

    rc = dht_file_send_reject(&w->dht, friend_number, file_number);
    if(rc < 0){
        IOEX_set_error(rc);
        return -1;
    }

    return 0;
}

int IOEX_send_file_pause(IOEXCarrier *w, const char *friendid, const char *fileindex)
{
    uint32_t friend_number;
    uint32_t file_number;
    int rc;

    if(!w || !friendid || !fileindex){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }
    if(!is_valid_key(friendid)){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }
    if(!w->is_ready){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_READY));
        return -1;
    }
    
    rc = get_friend_number(w, friendid, &friend_number);
    if(rc < 0){
        IOEX_set_error(rc);
        return -1;
    }

    file_number = strtoul(fileindex, NULL, 10);
    FileTracker *tracker = NULL;
    if(is_sender(file_number)){
        tracker = find_file_sender(w, friend_number, file_number);
    }
    else {
        tracker = find_file_receiver(w, friend_number, file_number);
    }
    if(tracker == NULL){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_FILE_TRACKER_INVALID));
        return -1;
    }

    rc = dht_file_send_pause(&w->dht, friend_number, file_number);
    if(rc < 0){
        IOEX_set_error(rc);
        return -1;
    }

    return 0;
}

int IOEX_send_file_resume(IOEXCarrier *w, const char *friendid, const char *fileindex)
{
    uint32_t friend_number;
    uint32_t file_number;
    int rc;

    if(!w || !friendid || !fileindex){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }
    if(!is_valid_key(friendid)){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }
    if(!w->is_ready){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_READY));
        return -1;
    }
    
    rc = get_friend_number(w, friendid, &friend_number);
    if(rc < 0){
        IOEX_set_error(rc);
        return -1;
    }

    file_number = strtoul(fileindex, NULL, 10);
    FileTracker *tracker = NULL;
    if(is_sender(file_number)){
        tracker = find_file_sender(w, friend_number, file_number);
    }
    else {
        tracker = find_file_receiver(w, friend_number, file_number);
    }
    if(tracker == NULL){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_FILE_TRACKER_INVALID));
        return -1;
    }

    rc = dht_file_send_resume(&w->dht, friend_number, file_number);
    if(rc < 0){
        IOEX_set_error(rc);
        return -1;
    }

    return 0;
}

int IOEX_send_file_cancel(IOEXCarrier *w, const char *friendid, const char *fileindex)
{
    uint32_t friend_number;
    uint32_t file_number;
    int rc;

    if(!w || !friendid || !fileindex){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }
    if(!is_valid_key(friendid)){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_INVALID_ARGS));
        return -1;
    }
    if(!w->is_ready){
        IOEX_set_error(IOEX_GENERAL_ERROR(IOEXERR_NOT_READY));
        return -1;
    }
    
    rc = get_friend_number(w, friendid, &friend_number);
    if(rc < 0){
        IOEX_set_error(rc);
        return -1;
    }

    file_number = strtoul(fileindex, NULL, 10);
    FileTracker *tracker = NULL;
    if(is_sender(file_number)){
        tracker = find_file_sender(w, friend_number, file_number);
        remove_file_sender(w, tracker);
    }
    else {
        // Remove the file if we are receiver side
        char fullpath[IOEX_MAX_FULL_PATH_LEN + 1];
        tracker = find_file_receiver(w, friend_number, file_number);
        if(get_fullpath(tracker, fullpath)){
            unlink(fullpath);
        }
        remove_file_receiver(w, tracker);
    }

    rc = dht_file_send_cancel(&w->dht, friend_number, file_number);
    if(rc < 0){
        IOEX_set_error(rc);
        return -1;
    }

    return 0;
}
#if defined(_WIN32) || defined(_WIN64)
#define __thread        __declspec(thread)
#endif

#if defined(_WIN32) || defined(_WIN64) || defined(__linux__)
static __thread int IOEX_error;
#elif defined(__APPLE__)
#include <pthread.h>
static pthread_once_t IOEX_key_once = PTHREAD_ONCE_INIT;
static pthread_key_t IOEX_error;
static void IOEX_setup_error(void)
{
    (void)pthread_key_create(&IOEX_error, NULL);
}
#else
#error "Unsupported OS yet"
#endif

int IOEX_get_error(void)
{
#if defined(_WIN32) || defined(_WIN64) || defined(__linux__)
    return IOEX_error;
#elif defined(__APPLE__)
    return (int)pthread_getspecific(IOEX_error);
#else
#error "Unsupported OS yet"
#endif
}

void IOEX_clear_error(void)
{
#if defined(_WIN32) || defined(_WIN64) || defined(__linux__)
    IOEX_error = IOEXSUCCESS;
#elif defined(__APPLE__)
    (void)pthread_setspecific(IOEX_error, 0);
#else
#error "Unsupported OS yet"
#endif
}

void IOEX_set_error(int err)
{
#if defined(_WIN32) || defined(_WIN64) || defined(__linux__)
    IOEX_error = err;
#elif defined(__APPLE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
    (void)pthread_once(&IOEX_key_once, IOEX_setup_error);
    (void)pthread_setspecific(IOEX_error, (void*)err);
#pragma GCC diagnostic pop
#else
#error "Unsupported OS yet"
#endif
}

