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

#ifndef __FRIENDINFOS_H__
#define __FRIENDINFOS_H__

#include <assert.h>
#include <stddef.h>
#include <linkedhashtable.h>

#include "IOEX_carrier.h"

typedef struct FriendInfo {
    HashEntry he;

    uint32_t friend_number;
    IOEXFriendInfo info;
} FriendInfo;

static
int friendid_compare(const void *key1, size_t len1, const void *key2, size_t len2)
{
    assert(key1 && sizeof(uint32_t) == len1);
    assert(key2 && sizeof(uint32_t) == len2);

    return strcmp(key1, key2);
}

static inline
Hashtable *friends_create(void)
{
    return hashtable_create(32, 1, NULL, friendid_compare);
}

static inline
int friends_exist(Hashtable *friends, uint32_t friend_number)
{
    assert(friends);
    assert(friend_number != UINT32_MAX);

    return hashtable_exist(friends, &friend_number, sizeof(uint32_t));
}

static inline
void friends_put(Hashtable *friends, FriendInfo *fi)
{
    assert(friends);
    assert(fi);

    fi->he.data = fi;
    fi->he.key = &fi->friend_number;
    fi->he.keylen = sizeof(uint32_t);

    hashtable_put(friends, &fi->he);
}

static inline
FriendInfo *friends_get(Hashtable *friends, uint32_t friend_number)
{
    assert(friends);
    assert(friend_number != UINT32_MAX);

    return (FriendInfo *)hashtable_get(friends, &friend_number, sizeof(uint32_t));
}

static inline
FriendInfo *friends_remove(Hashtable *friends, uint32_t friend_number)
{
    assert(friends);
    assert(friend_number != UINT32_MAX);

    return hashtable_remove(friends, &friend_number, sizeof(uint32_t));
}

static inline
void friends_clear(Hashtable *friends)
{
    assert(friends);
    hashtable_clear(friends);
}

static inline
HashtableIterator *friends_iterate(Hashtable *friends,
                                   HashtableIterator *iterator)
{
    assert(friends && iterator);
    return hashtable_iterate(friends, iterator);
}

static inline
int friends_iterator_next(HashtableIterator *iterator, FriendInfo **info)
{
    assert(iterator && info);
    return hashtable_iterator_next(iterator, NULL, NULL, (void **)info);
}

static inline
int friends_iterator_has_next(HashtableIterator *iterator)
{
    assert(iterator);
    return hashtable_iterator_has_next(iterator);
}

#endif /* __FRIENDINFOS_H__ */
