#ifndef __TSFILE_H__
#define __TSFILE_H__

#include "IOEX_session.h"

#define TSFile_NULL_data -1

#define Max_TSFile_config 5

#define Count_WaitStateChange 10000

#define Size_TSBuffer 2*1024

#define Size_FileName_Buffer 512
#define Size_Path_SaveFile_Buffer 512
/**
 *	Tranfer file config
 *	Record all info and config about transfer file
 *
 */
struct struct_TSFile_config{
	IOEXSession *ws;
    char filename[Size_FileName_Buffer];
	char RealFileName[Size_Path_SaveFile_Buffer+Size_FileName_Buffer];
    size_t file_size;
    size_t start_Position;
	int stream;
	char address[256];
    int state;

	//unused   
    int owner;
	int count;	
};

char Path_SaveReceiveFile[Size_Path_SaveFile_Buffer];

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
	IOEX_TSFile_ErrorCode_OverBuffer=-5,
	
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
//static const char *header_start_file = "$1A#";
//static const char *header_replyok_file ="$2B#";
//static const char *header_end_file = "$9Z#";
//static const char *div_char=",";
#define header_start_file "$1A#"
#define header_replyok_file "$2B#"
#define header_end_file "$9Z#"
#define div_char ","

//static int MAX_buffer_size = 2048;

void (*ReceivedComplete)(const char *FileName,const char *Real_FileName);

CARRIER_API
int IOEX_TSFile_Init(IOEXCarrier *carrier, const char *Path_Savefile);

CARRIER_API
int IOEX_TSFile_Request(IOEXCarrier *carrier, const char *address,
						const char* filename, int start_byte);

CARRIER_API
int IOEX_TSFile_ReceivedComplete_Callback(IOEXCarrier *carrier, void *callback);
#endif /* __TSFILE_H__ */
