#ifndef __TSFILE_H__
#define __TSFILE_H__

#include "IOEX_session.h"

#define TSFile_NULL_data -1

#define Max_TSFile_config 5

#define Count_WaitStateChange 10000

#define Size_TSBuffer 2*1024

/**
 *	Tranfer file config
 *	Record all info and config about transfer file
 *
 */
struct struct_TSFile_config{
	IOEXSession *ws;
    char filename[256];
	char RealFileName[256];
    size_t file_size;
    size_t start_Position;
	int stream;
	char address[256];
    int state;

	//unused   
    int owner;
	int count;	
};

struct struct_TSFile_config TSFile_config[Max_TSFile_config];

/**
 *	Error code of transfer file
 *	
 *
 */
typedef enum IOEX_TSFile_ErrorCode {
	IOEX_TSFile_ErrorCode_OK=0,
	IOEX_TSFile_ErrorCode_NoEmpty=-1,
	IOEX_TSFile_ErrorCode_NoFile=-2,
	IOEX_TSFile_ErrorCode_GetFriendInfoFail=-3,
	IOEX_TSFile_ErrorCode_FrinedNotOnLine=-4,
	
} IOEX_ErrorCode;

/**
 *	State about transfer file
 *	
 *
 */
typedef enum IOEX_TSFileState {
	IOEX_TSFileState_Nothing=0,
	IOEX_TSFileState_SendOutFileName = 11,
	IOEX_TSFileState_ReceiveFileName = 12,
	IOEX_TSFileState_SendOutFileData = 21,
	IOEX_TSFileState_ReceiveFileData = 22
} IOEX_TSFileState;


/**
 *	keyword for transfer file
 *	
 *
 */
static const char *header_start_file = "$1A#";
static const char *header_replyok_file ="$2B#";
static const char *header_end_file = "$9Z#";

static const char *div_char=",";
static int MAX_buffer_size = 2048;

//void (*ReceivedComplete)(const char *FileName,const char *Real_FileName);
void (*ReceivedComplete)(const char *FileName,const char *Real_FileName);
/*
typedef struct TSFile_Callbacks {

	void (*ReceivedComplete)(const char *FileName,const char *Real_FileName);
}TSFile_Callbacks;
*/
CARRIER_API
int IOEX_TSFile_Init(IOEXCarrier *carrier, void *context);

CARRIER_API
int IOEX_TSFile_Request(IOEXCarrier *carrier, const char *address,
						const char* filename, int start_byte, void *context);

CARRIER_API
int IOEX_TSFile_ReceivedComplete_Callback(IOEXCarrier *carrier, void *callback);
#endif /* __TSFILE_H__ */
