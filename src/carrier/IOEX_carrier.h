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

#ifndef __IOEX_CARRIER_H__
#define __IOEX_CARRIER_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>

#if defined(__APPLE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdocumentation"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CARRIER_STATIC)
  #define CARRIER_API
#elif defined(CARRIER_DYNAMIC)
  #ifdef CARRIER_BUILD
    #if defined(_WIN32) || defined(_WIN64)
      #define CARRIER_API        __declspec(dllexport)
    #else
      #define CARRIER_API        __attribute__((visibility("default")))
    #endif
  #else
    #if defined(_WIN32) || defined(_WIN64)
      #define CARRIER_API        __declspec(dllimport)
    #else
      #define CARRIER_API
    #endif
  #endif
#else
  #define CARRIER_API
#endif

/**
 * \~English
 * Carrier User address max length.
 */
#define IOEX_MAX_ADDRESS_LEN             52

/**
 * \~English
 * Carrier Node/User ID max length.
 */
#define IOEX_MAX_ID_LEN                  45

/**
 * \~English
 * Carrier user name max length.
 */
#define IOEX_MAX_USER_NAME_LEN           63

/**
 * \~English
 * Carrier user description max length.
 */
#define IOEX_MAX_USER_DESCRIPTION_LEN    127

/**
 * \~English
 * Carrier user phone number max length.
 */
#define IOEX_MAX_PHONE_LEN               31

/**
 * \~English
 * Carrier user email address max length.
 */
#define IOEX_MAX_EMAIL_LEN               127

/**
 * \~English
 * Carrier user region max length.
 */
#define IOEX_MAX_REGION_LEN              127

/**
 * \~English
 * Carrier user gender max length.
 */
#define IOEX_MAX_GENDER_LEN              31

/**
 * \~English
 * Carrier node name max length.
 */
#define IOEX_MAX_NODE_NAME_LEN           63

/**
 * \~English
 * Carrier node description max length.
 */
#define IOEX_MAX_NODE_DESCRIPTION_LEN    127

/**
 * \~English
 * Carrier App message max length.
 */
#define IOEX_MAX_APP_MESSAGE_LEN         1024

/**
 * \~English
 * Carrier file key max length in bytes.
 */
#define IOEX_MAX_FILE_KEY_LEN            32

/**
 * \~English
 * Carrier file id max length.
 */
#define IOEX_MAX_FILE_ID_LEN             IOEX_MAX_ID_LEN

/**
 * \~English
 * Carrier file name max length.
 */
#define IOEX_MAX_FILE_NAME_LEN           511

/**
 * \~English
 * Carrier file path max length.
 */
#define IOEX_MAX_FILE_PATH_LEN           511

/**
 * \~English
 * Carrier file full path max length.
 */
#define IOEX_MAX_FULL_PATH_LEN           (IOEX_MAX_FILE_NAME_LEN + IOEX_MAX_FILE_PATH_LEN + 1)

typedef struct IOEXCarrier IOEXCarrier;

/******************************************************************************
 * Creation & destruction
 *****************************************************************************/

/**
 * \~English
 * Bootstrap defines a couple of perperities to provide for Carrier nodes
 * to connect with. The bootstrap nodes help Carrier nodes be connected to
 * the others with more higher possibilities.
 */
typedef struct BootstrapNode {
    /**
     * \~English
     * The ip address supported with ipv4 protocol.
     */
    const char *ipv4;

    /**
     * \~English
     * The ip address supported with ipv6 protocol.
     */
    const char *ipv6;

    /**
     * \~English
     * The ip port.
     * The default value is 33445.
     */
    const char *port;

    /**
     * \~English
     * The unique public key to provide for Carrier nodes, terminated
     * by null-string.
     * The length of public key is about 45 bytes.
     */
    const char *public_key;
} BootstrapNode;

/**
 * \~English
 * IOEXOptions defines several settings that control the way the Carrier
 * node connects to others.
 *
 * @remark
 *      Default values are not defined for persistent_location of Carrier-
 *      Options, so application should be set persistent_location clearly.
 *      If the IOEXOptions structure is defined as a static variable,
 *      initialization (in compliant compilers) sets all values to 0 (NULL
 *      for pointers).
 */
typedef struct IOEXOptions {
    /**
     * \~English
     * The application defined persistent data location.
     * The location must be set.
     */
    const char *persistent_location;

    /**
     * \~English
     * The option to decide to use udp transport or not. Setting this option
     * to false will force Carrier node to use TCP only, which will potentially
     * slow down the message to run through.
     */
    bool udp_enabled;

    /**
     * \~English
     * The total number of bootstrap nodes to connect.
     * There must have at least one bootstrap node for the very first time
     * to create carrier instance.
     */
    size_t bootstraps_size;

    /**
     * \~English
     * The array of bootstrap nodes.
     */
    BootstrapNode *bootstraps;
} IOEXOptions;

/**
 * \~English
 * Get the current version of Carrier node.
 */
CARRIER_API
const char *IOEX_get_version(void);

/**
 * \~English
 * Get last commit hash of current Carrier node.
 */
CARRIER_API
const char *IOEX_get_last_commit(void);

/**
 * \~English
 * Get building timestamp of current Carrier node.
 */
CARRIER_API
const char *IOEX_get_build_time(void);

/**
 * \~English
 * Carrier log level to control or filter log output.
 */
typedef enum IOEXLogLevel {
    /**
     * \~English
     * Log level None
     * Indicate disable log output.
     */
    IOEXLogLevel_None = 0,
    /**
     * \~English
     * Log level fatal.
     * Indicate output log with level 'Fatal' only.
     */
    IOEXLogLevel_Fatal = 1,
    /**
     * \~English
     * Log level error.
     * Indicate output log above 'Error' level.
     */
    IOEXLogLevel_Error = 2,
    /**
     * \~English
     * Log level warning.
     * Indicate output log above 'Warning' level.
     */
    IOEXLogLevel_Warning = 3,
    /**
     * \~English
     * Log level info.
     * Indicate output log above 'Info' level.
     */
    IOEXLogLevel_Info = 4,
    /*
     * \~English
     * Log level debug.
     * Indicate output log above 'Debug' level.
     */
    IOEXLogLevel_Debug = 5,
    /*
     * \~English
     * Log level trace.
     * Indicate output log above 'Trace' level.
     */
    IOEXLogLevel_Trace = 6,
    /*
     * \~English
     * Log level verbose.
     * Indicate output log above 'Verbose' level.
     */
    IOEXLogLevel_Verbose = 7
} IOEXLogLevel;

/**
 * \~English
 * Carrier node connection status to Carrier network.
 */
typedef enum IOEXConnectionStatus {
    /**
     * \~English
     * Carrier node connected to Carrier network.
     * Indicate the Carrier node is online.
     */
    IOEXConnectionStatus_Connected,
    /**
     * \~English
     * There is no connection to Carrier network.
     * Indicate the Carrier node is offline.
     */
    IOEXConnectionStatus_Disconnected,
} IOEXConnectionStatus;

/**
 * \~English
 * Carrier node presence status to Carrier network.
 */
typedef enum IOEXPresenceStatus {
    /**
     * \~English
     * Carrier node is online and available.
     */
    IOEXPresenceStatus_None,
    /**
     * \~English
     * Carrier node is being away.
     * Carrier node can set this value with an user defined inactivity time.
     */
    IOEXPresenceStatus_Away,
    /**
     * \~English
     * Carrier node is being busy.
     * Carrier node can set this value to tell friends that it can not
     * currently wish to commincate.
     */
    IOEXPresenceStatus_Busy,
} IOEXPresenceStatus;

/**
 * \~English
 * A structure representing the Carrier user information.
 *
 * In Carrier SDK, self and all friends are carrier user, and have
 * same user attributes.
 */
typedef struct IOEXUserInfo {
    /**
     * \~English
     * User ID. Read only to application.
     */
    char userid[IOEX_MAX_ID_LEN+1];
    /**
     * \~English
     * Nickname, also known as display name.
     */
    char name[IOEX_MAX_USER_NAME_LEN+1];
    /**
     * \~English
     * User's description, also known as what's up.
     */
    char description[IOEX_MAX_USER_DESCRIPTION_LEN+1];
    /**
     * \~English
     * If user has an avatar.
     */
    int has_avatar;
    /**
     * \~English
     * User's gender.
     */
    char gender[IOEX_MAX_GENDER_LEN+1];
    /**
     * \~English
     * User's phone number.
     */
    char phone[IOEX_MAX_PHONE_LEN+1];
    /**
     * \~English
     * User's email address.
     */
    char email[IOEX_MAX_EMAIL_LEN+1];
    /**
     * \~English
     * User's region information.
     */
    char region[IOEX_MAX_REGION_LEN+1];
} IOEXUserInfo;

/**
 * \~English
 * A structure representing the Carrier friend information.
 *
 * Include the basic user information and the extra friend information.
 */
typedef struct IOEXFriendInfo {
    /**
     * \~English
     * Friend's user information.
     */
    IOEXUserInfo user_info;
    /**
     * \~English
     * Your label for the friend.
     */
    char label[IOEX_MAX_USER_NAME_LEN+1];
    /**
     * \~English
     * Friend's connection status.
     */
    IOEXConnectionStatus status;
    /**
     * \~English
     * Friend's presence status.
     */
    IOEXPresenceStatus presence;
} IOEXFriendInfo;

/**
 * \~English
 * File tracker data structure.
 * It is used to track and map file name, key, id, and (friend_number, file_index) pair.
 * It is important to update trackers correctly in carrier APIs and callbacks.
 */
typedef struct IOEXTrackerInfo {
    /**
     * \~English
     * File's unique ID. Randomly generated while sending file request.
     */
    uint8_t file_key[IOEX_MAX_FILE_KEY_LEN];
    /**
     * \~English
     * File's readable ID. It is file_key that encoded with base58.
     */
    char file_id[IOEX_MAX_FILE_ID_LEN+1];
    /**
     * \~English
     * File's name.
     */
    char file_name[IOEX_MAX_FILE_NAME_LEN+1];
    /**
     * \~English
     * File's storage path.
     */
    char file_path[IOEX_MAX_FILE_PATH_LEN+1];
    /**
     * \~English
     * The total size of the file.
     */
    uint64_t file_size;
    /**
     * \~English
     * Index of the friend who is the participant of this transmission.
     */
    uint32_t friend_number;
    /**
     * \~English
     * Index to identify this file transmission.
     * TOX use (friend_number, file_index) pair to identify a file transmission.
     */
    uint32_t file_index;
} IOEXTrackerInfo;

/**
 * \~English
 * File transmission status.
 */
typedef enum IOEXFileTransmissionStatus {
    /**
     * \~English
     * No file transmission.
     */
    IOEXFileTransmissionStatus_None,
    /**
     * \~English
     * File transmission request is sent, and is currently waiting for response
     */
    IOEXFileTransmissionStatus_Pending,
    /**
     * \~English
     * File is transmitting.
     */
    IOEXFileTransmissionStatus_Running,
    /**
     * \~English
     * File transmission is finished.
     */
    IOEXFileTransmissionStatus_Finished
} IOEXFileTransmissionStatus;

/**
 * \~English
 * File transmission paused status.
 */
typedef enum IOEXFileTransmissionPausedStatus {
    /**
     * \~English
     * File transmission is running. No one paused.
     */
    IOEXFileTransmissionPausedStatus_None,
    /**
     * \~English
     * File transmission is paused by us.
     */
    IOEXFileTransmissionPausedStatus_Us,
    /**
     * \~English
     * File transmission is paused by the other.
     */
    IOEXFileTransmissionPausedStatus_Other,
    /**
     * \~English
     * File transmission is paused by both.
     */
    IOEXFileTransmissionPausedStatus_Both
} IOEXFileTransmissionPausedStatus;

/**
 * \~English
 * File transmission direction.
 */
typedef enum IOEXFileTransmissionDirection {
    /**
     * \~English
     * Direction is unknown.
     */
    IOEXFileTransmissionDirection_Unknown,
    /**
     * \~English
     * We are the file sender.
     */
    IOEXFileTransmissionDirection_Send,
    /**
     * \~English
     * We are the file receiver.
     */
    IOEXFileTransmissionDirection_Receive
} IOEXFileTransmissionDirection;

/**
 * \~English
 * File transmission status.
 * This is the interface for applications who wants to know file transmission status.
 * The info are retrieved on the fly and should never be cached for future use.
 */
typedef struct IOEXFileInfo {
    /**
     * \~English
     * The copy of the correspond file tracker.
     */
    IOEXTrackerInfo ti;
    /**
     * \~English
     * The status of the transmission. None(0) if no tracker found.
     */
    IOEXFileTransmissionStatus status;
    /**
     * \~English
     * The paused status of the transmission. None(0) if no tracker found.
     */
    IOEXFileTransmissionPausedStatus paused;
    /**
     * \~English
     * The direction of the transmission. Unknown(0) if no tracker found.
     */
    IOEXFileTransmissionDirection direction;
    /**
     * \~English
     * The transferred size of the file. 0 if no tracker found.
     */
    uint64_t transferred_size;
} IOEXFileInfo;

/**
 * \~English
 * Carrier callbacks, include all global callbacks for Carrier.
 */
typedef struct IOEXCallbacks {
    /**
     * \~English
     * An application-defined function that perform idle work.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*idle)(IOEXCarrier *carrier, void *context);

    /**
     * \~English
     * An application-defined function that process the self connection status.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      status      [in] Current connection status. @see IOEXConnectionStatus.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*connection_status)(IOEXCarrier *carrier,
                              IOEXConnectionStatus status, void *context);

    /**
     * \~English
     * An application-defined function that process the ready notification.
     * Notice: application should wait this callback invoked before calling any
     * carrier function to interact with friends.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*ready)(IOEXCarrier *carrier, void *context);

    /**
     * \~English
     * An application-defined function that process the self info change event.
     * This callback is reserved for future compatibility.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      info        [in] The IOEXUserInfo pointer to the new user info.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*self_info)(IOEXCarrier *carrier, const IOEXUserInfo *info, void *context);

    /**
     * \~English
     * An application-defined function that iterate the each friends list item.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      info        [in] A pointer to IOEXFriendInfo structure that
     *                       representing a friend
     * @param
     *      context     [in] The application defined context data.
     *
     * @return
     *      Return true to continue iterate next friend user info,
     *      false to stop iterate.
     */
    bool (*friend_list)(IOEXCarrier *carrier, const IOEXFriendInfo* info,
                        void* context);

    /**
     * \~English
     * An application-defined function that process the friend connection
     * change event.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      friendid    [in] The friend's user id.
     * @param
     *      status      [in] Connection status. @see IOEXConnectionStatus
     * @param
     *      context     [in] The application defined context data.
     */
    void (*friend_connection)(IOEXCarrier *carrier,const char *friendid,
                              IOEXConnectionStatus status, void *context);

    /**
     * \~English
     * An application-defined function that process the friend information
     * change event.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      friendid    [in] The friend's user id.
     * @param
     *      info        [in] The IOEXFriendInfo pointer to the new friend info.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*friend_info)(IOEXCarrier *carrier, const char *friendid,
                        const IOEXFriendInfo *info, void *context);

    /**
     * \~English
     * An application-defined function that process the friend presence
     * change event.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      friendid    [in] The friend's user id.
     * @param
     *      presence    [in] The presence status of the friend.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*friend_presence)(IOEXCarrier *carrier, const char *friendid,
                            IOEXPresenceStatus presence, void *context);

    /**
     * \~English
     * An application-defined function that process the friend request.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      userid      [in] The user id who wants friend with us.
     * @param
     *      info        [in] The basic user info who wants to be friend.
     * @param
     *      hello       [in] PIN for target user, or any application defined
     *                       content.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*friend_request)(IOEXCarrier *carrier, const char *userid,
                           const IOEXUserInfo *info,
                           const char *hello, void *context);

    /**
     * \~English
     * An application-defined function that process the new friend added
     * event.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      info        [in] The firend's information.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*friend_added)(IOEXCarrier *carrier, const IOEXFriendInfo *info,
                         void *context);

    /**
     * \~English
     * An application-defined function that process the friend removed
     * event.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      friendid    [in] The friend's user id.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*friend_removed)(IOEXCarrier *carrier, const char *friendid,
                           void *context);

    /**
     * \~English
     * An application-defined function that process the friend messages.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      from        [in] The user id from who send the message.
     * @param
     *      msg         [in] The message content.
     * @param
     *      len         [in] The message length in bytes.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*friend_message)(IOEXCarrier *carrier, const char *from,
                           const void *msg, size_t len, void *context);

    /**
     * \~English
     * An application-defined function that process the friend invite request.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      from        [in] The user id from who send the invite request.
     * @param
     *      data        [in] The application defined data send from friend.
     * @param
     *      len         [in] The data length in bytes.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*friend_invite)(IOEXCarrier *carrier, const char *from,
                          const void *data, size_t len, void *context);

    /**
     * \~English
     * An application-defined function that process the file query request.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      friendid    [in] The user id from who send the file query request.
     * @param
     *      filename    [in] The name of file which is queried by the friend.
     * @param
     *      message     [in] Extra message sent by the friend.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*file_queried)(IOEXCarrier *carrier, const char *friendid,
                         const char *filename, const char *message, void *context);
    /**
     * \~English
     * An application-defined function that process the file send request.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      fileid      [in] The unique id for this file transmission.
     * @param
     *      friendid    [in] The user id from who send the file send request.
     * @param
     *      filename    [in] The name of file which is requested to be sent from friend.
     * @param
     *      filesize    [in] The size of the file in bytes.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*file_request)(IOEXCarrier *carrier, const char *fileid, const char *friendid,
                         const char *filename, size_t filesize, void *context);

    /**
     * \~English
     * An application-defined function that process the control message from a friend.
     * This control message indicates that the friend has accepted our previous send file request.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      fileid      [in] The unique id for this file transmission.
     * @param
     *      friendid    [in] The user id from who accepted our send file request.
     * @param
     *      fullpath    [in] The path and name of file which is accepted by the friend.
     * @param
     *      filesize    [in] The size of the file in bytes.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*file_accepted)(IOEXCarrier *carrier, const char *fileid, const char *friendid,
                          const char *fullpath, size_t filesize, void *context);

    /**
     * \~English
     * An application-defined function that process the control message from a friend.
     * This control message indicates that the friend has rejected our previous send file request.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      fileid      [in] The unique id for this file transmission.
     * @param
     *      friendid    [in] The user id from who rejected our send file request.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*file_rejected)(IOEXCarrier *carrier, const char *fileid, const char *friendid,
                          void *context);

    /**
     * \~English
     * An application-defined function that process the control message from a friend.
     * This control message indicates that the friend has paused one the currently transmitting file.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      fileid      [in] The unique id for this file transmission.
     * @param
     *      friendid    [in] The user id from who paused the file transmission.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*file_paused)(IOEXCarrier *carrier, const char *fileid, const char *friendid, 
                        void *context);

    /**
     * \~English
     * An application-defined function that process the control message from a friend.
     * This control message indicates that the friend has resumed one the currently transmitting file.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      fileid      [in] The unique id for this file transmission.
     * @param
     *      friendid    [in] The user id from who resumed the file transmission.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*file_resumed)(IOEXCarrier *carrier, const char *fileid, const char *friendid,
                         void *context);

    /**
     * \~English
     * An application-defined function that process the control message from a friend.
     * This control message indicates that the friend has canceled one the currently transmitting file.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      fileid      [in] The unique id for this file transmission.
     * @param
     *      friendid    [in] The user id from who canceled the file transmission.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*file_canceled)(IOEXCarrier *carrier, const char *fileid, const char *friendid,
                          void *context);

    /**
     * \~English
     * An application-defined function that is called when file transmission is completed.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      fileid      [in] The unique id for this file transmission.
     * @param
     *      friendid    [in] The user id who participant this file transmission.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*file_completed)(IOEXCarrier *carrier, const char *fileid, const char *friendid,
                           void *context);

    /**
     * \~English
     * An application-defined function that is called when file transmission is aborted.
     * File transmission abortion is usually caused by the disconnection of the friend.
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      fileid      [in] The unique id for this file transmission.
     * @param
     *      friendid    [in] The user id who participant this file transmission.
     * @param
     *      filename    [in] The name of the file that is transmitting.
     * @param
     *      length      [in] The length of the transmitted data in bytes.
     * @param
     *      filesize    [in] Total size of the file.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*file_aborted)(IOEXCarrier *carrier, const char *fileid, const char *friendid,
                         const char *filename, size_t length, size_t filesize, void *context);

    /**
     * \~English
     * An application-defined function that serves as file transmission progress callback
     *
     * @param
     *      carrier     [in] A handle to the Carrier node instance.
     * @param
     *      fileid      [in] The unique id for this file transmission.
     * @param
     *      friendid    [in] The user id who participant this file transmission.
     * @param
     *      fullpath    [in] The path with name of the local file.
     * @param
     *      size        [in] The total size in byte of this file.
     * @param
     *      transferred [in] The transferred size in byte of this file.
     * @param
     *      context     [in] The application defined context data.
     */
    void (*file_progress)(IOEXCarrier *carrier, const char *fileid, const char *friendid,
                          const char *fullpath, uint64_t size, uint64_t transferred,
                          void *context);
} IOEXCallbacks;

/**
 * \~English
 * initialize log options for Carrier. The default level to control log output
 * is 'Info'.
 *
 * @param
 *      level       [in] The log level to control internal log output.
 * @param
 *      log_file    [in] the log file name.
 *                       If the log_file is NULL, Carrier will not write
 *                       log to file.
 * @param
 *      log_printer [in] the user defined log printer. can be NULL.
 */
CARRIER_API
void IOEX_log_init(IOEXLogLevel level, const char *log_file,
                  void (*log_printer)(const char *format, va_list args));

/**
 * \~English
 * Check if the carrier address is valid.
 *
 * @param
 *      address     [in] the carrier address to be check.
 *
 * @return
 *      true if address is valid, or false if address is not valid.
 */
CARRIER_API
bool IOEX_address_is_valid(const char *address);

/**
 * \~English
 * Check if the carrier ID is valid.
 *
 * @param
 *      id          [in] the carrier id to be check.
 *
 * @return
 *      true if id is valid, or false if id is not valid.
 */
CARRIER_API
bool IOEX_id_is_valid(const char *id);

/**
 * \~English
 * Extract carrier userid (or nodeid) from the carrier address.
 *
 * @param
 *      address     [in] the carrier address to be check.
 * @param
 *      userid      [in] the buffer to save the extracted userid.
 * @param
 *      len         [in] the length of buffer.
 *
 * @return
 *      If no error occurs, return the pointer of extraced userid.
 *      Otherwise, return NULL, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
char *IOEX_get_id_by_address(const char *address, char *userid, size_t len);

/**
 * \~English
 * Create a new Carrier node instance. after creating the instance, it's
 * ready for connection to Carrier network.
 *
 * @param
 *      options     [in] A pointer to a valid IOEXOptions structure.
 * @param
 *      callbacks   [in] The Application defined callback functions.
 * @param
 *      context     [in] The application defined context data.
 *
 * @return
 *      If no error occurs, return the pointer of Carrier node instance.
 *      Otherwise, return NULL, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
IOEXCarrier *IOEX_new(const IOEXOptions *options,
                    IOEXCallbacks *callbacks, void *context);

/**
 * \~English
 * Disconnect from Carrier network, and destroy all associated resources
 * with the Carrier node instance.
 *
 * After calling the function, the Carrier pointer becomes invalid.
 * No other functions can be called.
 *
 * @param
 *      carrier     [in] A handle identifying the Carrier node instance
 *                       to kill.
 */
CARRIER_API
void IOEX_kill(IOEXCarrier *carrier);

/******************************************************************************
 * \~English
 * Connection & event loop
 *****************************************************************************/
/**
 * \~English
 * Attempts to connect the node to Carrier network. If the node successfully
 * connects to Carrier network, then it starts the node's main event loop.
 * The connect options was specified by previously create options.
 * @see IOEX_new().
 *
 * @param
 *      carrier     [in] A handle identifying the Carrier node instance.
 * @param
 *      interval    [in] Internal loop interval, in milliseconds.
 *
 * @return
 *      0 if the client successfully connected to Carrier network and start the
 *      event loop. Otherwise, return -1, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_run(IOEXCarrier *carrier, int interval);

/******************************************************************************
 * Internal node information
 *****************************************************************************/

/**
 * \~English
 * Get user address associated with the Carrier node.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      address     [out] The buffer that will receive the address.
 *                        The buffer size should at least
 *                        (IOEX_MAX_ADDRESS_LEN + 1) bytes.
 * @param
 *      len         [in] The buffer size of address.
 *
 * @return
 *      The address string pointer, or NULL if buffer is too small.
 */
CARRIER_API
char *IOEX_get_address(IOEXCarrier *carrier, char *address, size_t len);

/**
 * \~English
 * Get node identifier associated with this Carrier node.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      nodeid      [out] The buffer that will receive the identifier.
 *                        The buffer size should at least
 *                        (IOEX_MAX_ID_LEN + 1) bytes.
 * @param
 *      len         [in] The buffer size of nodeid.
 *
 * @return
 *      The nodeId string pointer, or NULL if buffer is too small.
 */
CARRIER_API
char *IOEX_get_nodeid(IOEXCarrier *carrier, char *nodeid, size_t len);

/**
 * \~English
 * Get user identifier associated with this Carrier node.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      userid      [out] The buffer that will receive the identifier.
 *                        The buffer size should at least
 *                        (IOEX_MAX_ID_LEN + 1) bytes.
 * @param
 *      len         [in] The buffer size of userid.
 *
 * @return
 *      The userId string pointer, or NULL if buffer is too small.
 */
CARRIER_API
char *IOEX_get_userid(IOEXCarrier *carrier, char *userid, size_t len);

/******************************************************************************
 * Client information
 *****************************************************************************/

/**
 * \~Egnlish
 * Update the nospam for Carrier address.
 *
 * Update the 4-byte nospam part of the Carrier address with host byte order
 * expected. Nospam for Carrier address is used to eliminate spam friend
 * request.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      nospam      [in] An 4-bytes unsigned integer.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_set_self_nospam(IOEXCarrier *carrier, uint32_t nospam);

/**
 * \~Egnlish
 * Get the nospam for Carrier address.
 *
 * Get the 4-byte nospam part of the Carrier address with host byte order
 * expected. Nospam for Carrier address is used to eliminate spam friend
 * request.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      nospam      [in] An unsigned integer pointer to receive nospam value.
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_get_self_nospam(IOEXCarrier *carrier, uint32_t *nospam);

/**
 * \~English
 * Update self information.
 *
 * As self information changed, Carrier node would update itself information
 * to Carrier network, which would forward the change to all friends.
 * nodes.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      info        [in] The IOEXUserInfo pointer to the updated user info.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_set_self_info(IOEXCarrier *carrier, const IOEXUserInfo *info);

/**
 * \~English
 * Get self information.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      info        [in] The IOEXUserInfo pointer to receive user info.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_get_self_info(IOEXCarrier *carrier, IOEXUserInfo *info);

/**
 * \~English
 * Set self presence status.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      presence    [in] the new presence status.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_set_self_presence(IOEXCarrier *carrier, IOEXPresenceStatus presence);

/**
 * \~English
 * Get self presence status.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      presence    [in] A pointer to receive presence status value.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_get_self_presence(IOEXCarrier *carrier, IOEXPresenceStatus *presence);

/**
 * \~English
 * Check if Carrier node instance is being ready.
 *
 * All carrier interactive APIs should be called only if carrier instance
 * is being ready.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 *
 * @return
 *      true if the carrier node instance is ready, or false if not.
 */
CARRIER_API
bool IOEX_is_ready(IOEXCarrier *carrier);

/******************************************************************************
 * Friend information
 *****************************************************************************/

/**
 * \~English
 * An application-defined function that iterate the each friends list item.
 *
 * IOEXFriendsIterateCallback is the callback function type.
 *
 * @param
 *      info        [in] A pointer to IOEXFriendInfo structure that
 *                       representing a friend
 * @param
 *      context     [in] The application defined context data.
 *
 * @return
 *      Return true to continue iterate next friend user info,
 *      false to stop iterate.
 */
typedef bool IOEXFriendsIterateCallback(const IOEXFriendInfo *info,
                                       void *context);

/**
 * \~English
 * Get friends list. For each friend will call the application defined
 * iterate callback.
 *
 * @param
 *      carrier     [in] a handle to the Carrier node instance.
 * @param
 *      callback    [in] a pointer to IOEXFriendsIterateCallback function.
 * @param
 *      context     [in] the application defined context data.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_get_friends(IOEXCarrier *carrier,
                    IOEXFriendsIterateCallback *callback, void *context);

/**
 * \~English
 * Get friend information.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      friendid    [in] The friend's user id.
 * @param
 *      info        [in] The IOEXFriendInfo pointer to receive the friend
 *                       information.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_get_friend_info(IOEXCarrier *carrier, const char *friendid,
                        IOEXFriendInfo *info);

/**
 * \~English
 * Set the label of the specified friend.
 *
 * If the value length is 0 or value is NULL, the attribute will be cleared.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      friendid    [in] The friend's user id.
 * @param
 *      label       [in] the new label of the specified friend.
 *
 * @return
 *      0 on success, or -1 if an error occurred. The specific error code
 *      can be retrieved by calling IOEX_get_error().
 *
 * @remarks
 *      The label of a friend is a private alias named by yourself. It can be
 *      seen by yourself only, and has no impact to the target friend.
 */
CARRIER_API
int IOEX_set_friend_label(IOEXCarrier *carrier,
                         const char *friendid, const char *label);

/**
 * \~English
 * Check if the user ID is friend.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      userid      [in] The userid to check.
 *
 * @return
 *      true if the user id is friend, or false if not;
 */
CARRIER_API
bool IOEX_is_friend(IOEXCarrier* carrier, const char* userid);

/******************************************************************************
 * Friend add & remove
 *****************************************************************************/

/**
 * \~English
 * Attempt to add friend by sending a new friend request.
 *
 * This function will add a new friend with specific address, and then
 * send a friend request to the target node.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      address     [in] The target user address.
 * @param
 *      hello       [in] PIN for target user, or any application defined
 *                       content.
 *
 * @return
 *      0 if adding friend is successful. Otherwise, return -1, and a specific
 *      error code can be retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_add_friend(IOEXCarrier *carrier, const char *address, const char *hello);

/**
 * \~English
 * Accept the friend request.
 *
 * This function is used to add a friend in response to a friend request.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      userid      [in] The user id to who wants to be friend with us.
 *
 * @return
 *      0 if adding friend successfully.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_accept_friend(IOEXCarrier *carrier, const char *userid);

/**
 * \~English
 * Remove a friend.
 *
 * This function will send a remove friend indicator to Carrier network.
 *
 * If all correct, Carrier network will clean the friend relationship, and
 * send friend removed message to both.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      userid      [in] The target user id.
 *
 * @return
 *      0 if the indicator successfully sent.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_remove_friend(IOEXCarrier *carrier, const char *userid);

/******************************************************************************
 * Application transactions between friends
 *****************************************************************************/

/**
 * \~English
 * Send a message to a friend.
 *
 * The message length may not exceed IOEX_MAX_APP_MESSAGE_LEN, and message
 * itself should be text-formatted. Larger messages must be split by application
 * and sent as separate messages. Other carrier nodes can reassemble the
 * fragments.
 *
 * Message may not be empty or NULL.
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      to          [in] The target userid.
 * @param
 *      msg         [in] The message content defined by application.
 * @param
 *      len         [in] The message length in bytes.
 *
 * @return
 *      0 if the text message successfully sent.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_send_friend_message(IOEXCarrier *carrier, const char *to,
                            const void *msg, size_t len);

/**
 * \~English
 * An application-defined function that process the friend invite response.
 *
 * CarrierFriendInviteResponseCallback is the callback function type.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      from        [in] The target user id.
 * @param
 *      status      [in] The status code of the response.
 *                       0 is success, otherwise is error.
 * @param
 *      reason      [in] The error message if status is error, or NULL
 * @param
 *      data        [in] The application defined data return by target user.
 * @param
 *      len         [in] The data length in bytes.
 * @param
 *      context      [in] The application defined context data.
 */
typedef void IOEXFriendInviteResponseCallback(IOEXCarrier *carrier,
                                             const char *from,
                                             int status, const char *reason,
                                             const void *data, size_t len,
                                             void *context);

/**
 * \~English
 * Send invite request to a friend.
 *
 * Application can attach the application defined data within the invite
 * request, and the data will send to target friend.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      to          [in] The target userid.
 * @param
 *      data        [in] The application defined data send to target user.
 * @param
 *      len         [in] The data length in bytes.
 * @param
 *      callback    [in] A pointer to IOEXFriendInviteResponseCallback
 *                       function to receive the invite response.
 * @param
 *      context      [in] The application defined context data.
 *
 * @return
 *      0 if the invite request successfully send to the friend.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_invite_friend(IOEXCarrier *carrier, const char *to,
                      const void *data, size_t len,
                      IOEXFriendInviteResponseCallback *callback,
                      void *context);

/**
 * \~English
 * Reply the friend invite request.
 *
 * This function will send a invite response to friend.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      to          [in] The userid who send invite request.
 * @param
 *      status      [in] The status code of the response.
 *                       0 is success, otherwise is error.
 * @param
 *      reason      [in] The error message if status is error, or NULL
 *                       if success.
 * @param
 *      data        [in] The application defined data send to target user.
 *                       If the status is error, this will be ignored.
 * @param
 *      len         [in] The data length in bytes.
 *                       If the status is error, this will be ignored.
 *
 * @return
 *      0 if the invite response successfully send to the friend.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_reply_friend_invite(IOEXCarrier *carrier, const char *to,
                            int status, const char *reason,
                            const void *data, size_t len);

/******************************************************************************
 * File transmitting
 *****************************************************************************/

/**
 * \~English
 * An application-defined function that iterate the each file transmission.
 *
 * IOEXFilesIterateCallback is the callback function type.
 *
 * @param
 *      info        [in] A pointer to IOEXTrackerInfo structure that
 *                       representing a file transmission.
 * @param
 *      context     [in] The application defined context data.
 *
 * @return
 *      Return true to continue iterate next file info,
 *      false to stop iterate.
 */
typedef bool IOEXFilesIterateCallback(int direction, const IOEXTrackerInfo *info,
                                      void *context);

/**
 * \~English
 * An application-defined function that process the file query request.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      friendid    [in] The user id whom we send the file query to.
 * @param
 *      filename    [in] The name of file we are querying for.
 * @param
 *      message     [in] Extra message we sent to friend.
 * @return
 *      0 if the request successfully send to the friend.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_send_file_query(IOEXCarrier *carrier, const char *friendid, const char *filename, const char *message);

/**
 * \~English
 * An application-defined function that process the file send request.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      fileid      [out] The buffer that used to store base58 encoded file id.
 *                        The size of the buffer should >= IOEX_MAX_ID_LEN (45).
 * @param
 *      id_len      [in] Size of the fileid buffer. It should >= IOEX_MAX_ID_LEN (45)
 * @param
 *      friendid    [in] The user id whom we send the file send request to.
 * @param
 *      filename    [in] The name of file which is requested to be sent from friend.
 * @return
 *      0 if the request successfully send to the friend.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_send_file_request(IOEXCarrier *carrier, char *fileid, size_t id_len, const char *friendid, const char *filename);

/**
 * \~English
 * An application-defined function that accepts a file send request.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      fileid      [in] The unique id of the file that will be accepted.
 * @param
 *      filename    [in] Rename the file as filename.
 * @param
 *      filepath    [in] The path to store the file.
 * @return
 *      0 if the request successfully send to the friend.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_send_file_accept(IOEXCarrier *carrier, const char *fileid,
                          const char *filename, const char *filepath);

/**
 * \~English
 * An application-defined function that sends file seek control.
 * This function must be called right after the file request is received, and before sending accept.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      fileid      [in] The unique id of the file that will be seeked.
 * @param
 *      position    [in] The start position of the file that should be sent.
 * @return
 *      0 if the request successfully send to the friend.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_send_file_seek(IOEXCarrier *carrier, const char *fileid,
                        const char *position);

/**
 * \~English
 * An application-defined function that rejects a file send request.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      fileid      [in] The unique id of the file that will be rejected.
 * @return
 *      0 if the request successfully send to the friend.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_send_file_reject(IOEXCarrier *carrier, const char *fileid);

/**
 * \~English
 * An application-defined function that pause a file transmission.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      fileid      [in] The unique id of the file that will be paused.
 * @return
 *      0 if the request successfully send to the friend.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_send_file_pause(IOEXCarrier *carrier, const char *fileid);

/**
 * \~English
 * An application-defined function that resume a file transmission.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      fileid      [in] The unique id of the file that will be resumed.
 * @return
 *      0 if the request successfully send to the friend.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_send_file_resume(IOEXCarrier *carrier, const char *fileid);

/**
 * \~English
 * An application-defined function that cancels a file transmission.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      fileid      [in] The unique id of the file that will be canceled.
 * @return
 *      0 if the request successfully send to the friend.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_send_file_cancel(IOEXCarrier *carrier, const char *fileid);

/**
 * \~English
 * An application-defined function that iteratively get file info.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      callback    [in] The iteration callback that will be called.
 * @param
 *      context     [in] The application defined context data.
 * @return
 *      0 if the request successfully send to the friend.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_get_files(IOEXCarrier *carrier, IOEXFilesIterateCallback *callback, void *context);

/**
 * \~English
 * An application-defined function that get file info.
 *
 * @param
 *      carrier     [in] A handle to the Carrier node instance.
 * @param
 *      fileinfo    [out] The buffer to store the file transmission info.
 * @param
 *      fileid      [in] The unique id of the file transmission.
 * @return
 *      0 if the request successfully send to the friend.
 *      Otherwise, return -1, and a specific error code can be
 *      retrieved by calling IOEX_get_error().
 */
CARRIER_API
int IOEX_get_file_info(IOEXCarrier *carrier, IOEXFileInfo *fileinfo, const char *fileid);

/******************************************************************************
 * Error handling
 *****************************************************************************/

#define IOEXSUCCESS                                  0

// Facility code
#define IOEXF_GENERAL                                0x01
#define IOEXF_SYS                                    0x02
#define IOEXF_HTTP                                   0x03
#define IOEXF_RESERVED2                              0x04
#define IOEXF_ICE                                    0x05
#define IOEXF_DHT                                    0x06

/**
 * \~English
 * Argument(s) is(are) invalid.
 */
#define IOEXERR_INVALID_ARGS                         0x01

/**
 * \~English
 * Runs out of memory.
 */
#define IOEXERR_OUT_OF_MEMORY                        0x02

/**
 * \~English
 * Buffer size is too small.
 */
#define IOEXERR_BUFFER_TOO_SMALL                     0x03

/**
 * \~English
 * Persistent data is corrupted.
 */
#define IOEXERR_BAD_PERSISTENT_DATA                  0x04

/**
 * \~English
 * Persistent file is invalid.
 */
#define IOEXERR_INVALID_PERSISTENCE_FILE             0x05

/**
 * \~English
 * Control packet is invalid.
 */
#define IOEXERR_INVALID_CONTROL_PACKET               0x06

/**
 * \~English
 * Credential is invalid.
 */
#define IOEXERR_INVALID_CREDENTIAL                   0x07

/**
 * \~English
 * Server failed.
 */
#define IOEXERR_SERVER_FAILED                        0x08

/**
 * \~English
 * Carrier ran already.
 */
#define IOEXERR_ALREADY_RUN                          0x09

/**
 * \~English
 * Carrier not ready.
 */
#define IOEXERR_NOT_READY                            0x0A

/**
 * \~English
 * The requested entity does not exist.
 */
#define IOEXERR_NOT_EXIST                            0x0B

/**
 * \~English
 * The entity exists already.
 */
#define IOEXERR_ALREADY_EXIST                        0x0C

/**
 * \~English
 * There are no matched requests.
 */
#define IOEXERR_NO_MATCHED_REQUEST                   0x0D

/**
 * \~English
 * User ID is invalid.
 */
#define IOEXERR_INVALID_USERID                       0x0E

/**
 * \~English
 * Node ID is invalid.
 */
#define IOEXERR_INVALID_NODEID                       0x0F

/**
 * \~English
 * APP ID is invalid.
 */
#define IOEXERR_INVALID_APPID                        0x10

/**
 * \~English
 * Descriptor is invalid.
 */
#define IOEXERR_INVALID_DESCRIPTOR                   0x11

/**
 * \~English
 * Failed because wrong state.
 */
#define IOEXERR_WRONG_STATE                          0x12

/**
 * \~English
 * Stream busy.
 */
#define IOEXERR_BUSY                                 0x13

/**
 * \~English
 * Language binding error.
 */
#define IOEXERR_LANGUAGE_BINDING                     0x14

/**
 * \~English
 * Encryption failed.
 */
#define IOEXERR_ENCRYPT                              0x15

/**
 * \~English
 * The content size of SDP is too long.
 */
#define IOEXERR_SDP_TOO_LONG                         0x16

/**
 * \~English
 * Bad SDP information format.
 */
#define IOEXERR_INVALID_SDP                          0x17

/**
 * \~English
 * Not implemented yet.
 */
#define IOEXERR_NOT_IMPLEMENTED                      0x18

/**
 * \~English
 * Limits are exceeded.
 */
#define IOEXERR_LIMIT_EXCEEDED                       0x19

/**
 * \~English
 * Allocate port unsuccessfully.
 */
#define IOEXERR_PORT_ALLOC                           0x1A

/**
 * \~English
 * Invalid proxy type.
 */
#define IOEXERR_BAD_PROXY_TYPE                       0x1B

/**
 * \~English
 * Invalid proxy host.
 */
#define IOEXERR_BAD_PROXY_HOST                       0x1C

/**
 * \~English
 * Invalid proxy port.
 */
#define IOEXERR_BAD_PROXY_PORT                       0x1D

/**
 * \~English
 * Proxy is not available.
 */
#define IOEXERR_PROXY_NOT_AVAILABLE                  0x1E

/**
 * \~English
 * Persistent data is encrypted, load failed.
 */
#define IOEXERR_ENCRYPTED_PERSISTENT_DATA            0x1F

/**
 * \~English
 * Invalid bootstrap host.
 */
#define IOEXERR_BAD_BOOTSTRAP_HOST                   0x20

/**
 * \~English
 * Invalid bootstrap port.
 */
#define IOEXERR_BAD_BOOTSTRAP_PORT                   0x21

/**
 * \~English
 * Data is too long.
 */
#define IOEXERR_TOO_LONG                             0x22

/**
 * \~English
 * Could not friend yourself.
 */
#define IOEXERR_ADD_SELF                             0x23

/**
 * \~English
 * Invalid address.
 */
#define IOEXERR_BAD_ADDRESS                          0x24

/**
 * \~English
 * Friend is offline.
 */
#define IOEXERR_FRIEND_OFFLINE                       0x25

/**
 * \~English
 * File cannot be stored.
 */
#define IOEXERR_FILE_DENY                            0x26

/**
 * \~English
 * File cannot be read.
 */
#define IOEXERR_FILE_INVALID                         0x27

/**
 * \~English
 * File already existed.
 */
#define IOEXERR_FILE_EXISTED                         0x28

/**
 * \~English
 * File tracker is invalid.
 */
#define IOEXERR_FILE_TRACKER_INVALID                 0x29

/**
 * \~English
 * Unknown error.
 */
#define IOEXERR_UNKNOWN                              0xFF

#define IOEX_MK_ERROR(facility, code)  (0x80000000 | ((facility) << 24) | \
                    ((((code) & 0x80000000) >> 8) | ((code) & 0x7FFFFFFF)))

#define IOEX_GENERAL_ERROR(code)       IOEX_MK_ERROR(IOEXF_GENERAL, code)
#define IOEX_SYS_ERROR(code)           IOEX_MK_ERROR(IOEXF_SYS, code)
#define IOEX_HTTP_ERROR(code)          IOEX_MK_ERROR(IOEXF_HTTP, code)
#define IOEX_ICE_ERROR(code)           IOEX_MK_ERROR(IOEXF_ICE, code)
#define IOEX_DHT_ERROR(code)           IOEX_MK_ERROR(IOEXF_DHT, code)

/*
 * \~English
 * Retrieves the last-error code value. The last-error code is maintained on a
 * per-instance basis. Multiple instance do not overwrite each other's
 * last-error code.
 *
 * @return
 *      The return value is the last-error code.
 */
CARRIER_API
int IOEX_get_error(void);

/**
 * \~English
 * Clear the last-error code of a Carrier instance.
 */
CARRIER_API
void IOEX_clear_error(void);

#ifdef __cplusplus
}
#endif

#if defined(__APPLE__)
#pragma GCC diagnostic pop
#endif

#endif /* __IOEX_CARRIER_H_ */
