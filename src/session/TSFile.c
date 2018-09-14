#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>

#include <rc_mem.h>
#include <time_util.h>
#include <vlog.h>
#include <unistd.h>
#include <sys/time.h>

#include "IOEX_session.h"
#include "services.h"
#include "TSFile.h"


void *thread_remove_stream(void *in_parm){

	int index=*((int *)in_parm);
	free(in_parm);	

	int rc;
	vlogD("[ANT]IOEX_TSFile_remove_stream,index=%d\n",index);

	vlogD("[ANT]IOEX_TSFile_remove_stream,%d,%d\n",TSFile_config[index].ws,TSFile_config[index].stream);
	rc = IOEX_session_remove_stream(TSFile_config[index].ws, TSFile_config[index].stream);
	if (rc < 0) {
	   	vlogD("[ANT]remove_stream failed.\n");
	}
	else {
		vlogD("[ANT]remove_stream successfully.\n");
	}

	IOEX_session_close(TSFile_config[index].ws);

	TSFile_config[index].ws=0;
	TSFile_config[index].stream=TSFile_NULL_data;
	TSFile_config[index].file_size=TSFile_NULL_data;
	TSFile_config[index].state=IOEX_TSFileState_Nothing;
	TSFile_config[index].start_Position=0;

	strcpy(TSFile_config[index].filename,"");
	strcpy(TSFile_config[index].RealFileName,"");
	strcpy(TSFile_config[index].address,"");
	vlogD("[ANT]IOEX_TSFile_remove_stream,003\n");

	return NULL;
}

void IOEX_TSFile_remove_stream(int index){
	pthread_attr_t attr;
	pthread_t th;

	if ( (index<0) ||(index>Max_TSFile_config) ){
		vlogE("IOEX_TSFile_remove_stream, index=%d error\n",index);
		return;
	}

	int *arg=malloc(sizeof(*arg));
	*arg=index;
		
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&th, &attr, thread_remove_stream, arg);
	pthread_attr_destroy(&attr);

}

int Get_TSFileConfig_Index(int inStream){
	int return_index=-1;
	int i;

	for (i=0;i<Max_TSFile_config;i++){
		if (TSFile_config[i].stream==inStream){
			return_index=i;
			break;
		}
	}
	return return_index;
}


static void session_request_complete_callback(IOEXSession *ws, int status,
                const char *reason, const char *sdp, size_t len, void *context)
{
	int rc;

    if (status != 0)
        return;

    rc = IOEX_session_start(ws, sdp,len);
}

void *thread_SendFile(void *in_parm){
	FILE *fp;
    char buffer[Size_TSBuffer];
	int rc;
	int TSFile_config_index=-1;

	int stream=*((int *)in_parm);
	free(in_parm);
	TSFile_config_index=stream;

	if ( (TSFile_config_index<0) ||(TSFile_config_index>Max_TSFile_config) ){
		vlogE("thread_SendFile, TSFile_config_index=%d error\n",TSFile_config_index);
		return NULL;
	}

	vlogD("[thread_SendFile]stream=%d\n", stream);
	vlogD("[thread_SendFile]ws=%d\n", TSFile_config[TSFile_config_index].ws);
	vlogE("thread_SendFile,TSFile_config_index=%d\n",TSFile_config_index);

	fp = fopen(TSFile_config[TSFile_config_index].filename, "r");	
	if (!fp){
		vlogE("[ant] open file fail \n");
		return NULL;
	}
	fseek(fp, 0, SEEK_END);
	size_t size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	size_t read_len=0;
	int temp_len=0;

	while(read_len<size){
		temp_len=size-read_len;
		if (temp_len>Size_TSBuffer){
			fread(buffer,1,Size_TSBuffer,fp);				
			read_len=read_len+Size_TSBuffer;
			rc = IOEX_stream_write(TSFile_config[TSFile_config_index].ws, 
								  TSFile_config[TSFile_config_index].stream,
                                  buffer, 
                                  Size_TSBuffer);
			if (rc<0){
				vlogE("[ANT]thread_SendFile1 fail, rc=%d\n" ,rc);
			}
		
		}else{
			fread(buffer,1,temp_len,fp);
			read_len=read_len+temp_len;
			rc = IOEX_stream_write(TSFile_config[TSFile_config_index].ws,
								  TSFile_config[TSFile_config_index].stream,
								  buffer, 
                                  temp_len);
			
		}
		usleep(200);
	}
	fclose(fp);
	
	strcpy(buffer,header_end_file);
	vlogD("[ant] SendFile, while over %s\n",buffer);
	sleep(2);
	rc = IOEX_stream_write(TSFile_config[TSFile_config_index].ws, 
								  TSFile_config[TSFile_config_index].stream,
                                  buffer, 
                                  Size_TSBuffer);
	if (rc<0){
		vlogE("[ANT]thread_SendFile2 fail, rc=%d\n" ,rc);
	}
	usleep(200);
	vlogD("[ant] SendFile, while over 2\n");

	return NULL;
}

static void MasterTSFile_stream_on_state_changed(IOEXSession *ws, int stream,
        IOEXStreamState state, void *context)
{
	const char *state_name[] = {
        "raw",
        "initialized",
        "transport_ready",
        "connecting",
        "connected",
        "deactivated",
        "closed",
        "failed"
    };

    vlogD("[ANT]MasterTSFile [%d] state changed to: %s\n", stream, state_name[state]);

	int TSFile_config_index=-1;
	char buffer[Size_TSBuffer];
	int rc;

	if (state==IOEXStreamState_connected){
		TSFile_config_index=Get_TSFileConfig_Index(stream);
		if (TSFile_config_index!=-1){
			if (TSFile_config[TSFile_config_index].state==IOEX_TSFileState_Nothing){
				strcpy(buffer,header_start_file);
				strcat(buffer,div_char);
				strcat(buffer,TSFile_config[TSFile_config_index].filename);
				strcat(buffer,div_char);
				vlogD("[ant] buffer=%s\n",buffer);
				TSFile_config[TSFile_config_index].ws=ws;
	  
				rc = IOEX_stream_write(ws, stream,buffer, strlen(buffer));
				if (rc>=0){
					TSFile_config[TSFile_config_index].state=IOEX_TSFileState_SendOutFileName;

				}
			}
		}
	}
	if (state==IOEXStreamState_closed){		
		TSFile_config_index=Get_TSFileConfig_Index(stream);
		if (TSFile_config_index!=-1){
			IOEX_TSFile_remove_stream(TSFile_config_index);
		}
	}
	
}

static void MasterTSFile_stream_on_data(IOEXSession *ws, int stream, const void *data,
                           size_t len, void *context)
{
	vlogD("MasterTSFile: [%d] received data [%.*s]\n", stream, (int)len, (char*)data);
	int TSFile_config_index=-1;
	pthread_attr_t attr;
	pthread_t th;
	
	TSFile_config_index=Get_TSFileConfig_Index(stream);
	char *p2;
	if (TSFile_config_index!=-1){
		p2=strstr(data,header_replyok_file);
		if (p2!=NULL){
			TSFile_config[TSFile_config_index].state=IOEX_TSFileState_SendOutFileData;
			//Start send file data
			int *arg=malloc(sizeof(*arg));
			*arg=TSFile_config_index;
		
			vlogD("MasterTSFile_stream_on_data, 0001,TSFile_config_index=%d",TSFile_config_index);
			pthread_attr_init(&attr);
			pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
			pthread_create(&th, &attr, thread_SendFile, arg);
			pthread_attr_destroy(&attr);

		}
	}

}

static void SlaveTSFile_stream_on_state_changed(IOEXSession *ws, int stream,
        IOEXStreamState state, void *context)
{
	const char *state_name[] = {
        "raw",
        "initialized",
        "transport_ready",
        "connecting",
        "connected",
        "deactivated",
        "closed",
        "failed"
    };

    vlogD("[ANT]SlaveTSFile [%d] state changed to: %s\n", stream, state_name[state]);

}

static void SlaveTSFile_stream_on_data(IOEXSession *ws, int stream, const void *data,
                           size_t len, void *context)
{
	char *p1,*p3;
	char *d1,*d2;
	int i;
	int TSFile_config_index=-1;
	int empty_index=-1;
	char file_name[Size_FileName_Buffer];
	char buffer[Size_TSBuffer];
	char temp_file_name[Size_FileName_Buffer];
	int rc;
	struct timeval tv;
	long FileName_long;

	p1=strstr(data,header_start_file);
	p3=strstr(data,header_end_file);

	if (p1!=NULL){	
		d1=strstr(data,div_char);
		if (d1!=NULL){
			d2=strstr(d1+1,div_char);
			if (d2!=NULL){
				memset(file_name, 0, sizeof(file_name));
				strncpy(file_name,d1+1,d2-d1-1);
				if (strlen(file_name)>Size_FileName_Buffer){
					vlogE("SlaveTSFile_stream_on_data, file name too long,=%d",strlen(file_name));
					return;
				}
				
				TSFile_config_index=Get_TSFileConfig_Index(stream);
				//vlogD("[ANT]SlaveTSFile_stream_on_data,stream=%d,TSFile_config_index=%d",stream,TSFile_config_index);
				if (TSFile_config_index!=-1){
					TSFile_config[TSFile_config_index].ws=ws;
					strcpy(TSFile_config[TSFile_config_index].RealFileName,file_name);
					gettimeofday(&tv,NULL);
					FileName_long=tv.tv_sec*1000+tv.tv_usec/1000;
					//sprintf(TSFile_config[TSFile_config_index].filename,"%ld.Xtmp",FileName_long);
					sprintf(temp_file_name,"%ld.Xtmp",FileName_long);
					strcat(TSFile_config[TSFile_config_index].filename,Path_SaveReceiveFile);
					strcat(TSFile_config[TSFile_config_index].filename,temp_file_name);

					vlogD("[DDXX]FileNam=%s",TSFile_config[TSFile_config_index].filename);
					TSFile_config[TSFile_config_index].start_Position=0;
					TSFile_config[TSFile_config_index].state=IOEX_TSFileState_ReceiveFileName;
					vlogD("[ANT]SlaveTSFile_stream_on_data,empty_index=%d",empty_index);

					strcpy(buffer,header_replyok_file);						
					rc = IOEX_stream_write(ws, stream,buffer, strlen(buffer));
				}
				
			}
		}
	}else
    if (p3!=NULL){	
		int res;
		res=strcmp(data,header_end_file);		
		TSFile_config_index=Get_TSFileConfig_Index(stream);
		vlogD("[ANT]transfile_on_data, res=%d,len=%d\n",res,len);
		if (TSFile_config_index!=-1){
			if ( (res>0) && (len>4) ){
				char end_buf[Size_TSBuffer];

				strncpy(end_buf,data,len-4);
				FILE *fptr;        
				fptr=fopen(TSFile_config[TSFile_config_index].filename,"a");
				fwrite(end_buf,1,len-4,fptr);
				fclose(fptr);
			}
		}
		//sleep(1);		
		callback_func_ReceivedComplete(TSFile_config[TSFile_config_index].filename,TSFile_config[TSFile_config_index].RealFileName);
		usleep(200);   
		IOEX_TSFile_remove_stream(TSFile_config_index);  
	}else{
		TSFile_config_index=Get_TSFileConfig_Index(stream);
		char end_data[4];
		strncpy(end_data, data+len-4,4);
		vlogD("TSFile_config_index=%d,file=%s,state=%d\n",
		TSFile_config_index,TSFile_config[TSFile_config_index].filename,TSFile_config[TSFile_config_index].state);
		if (TSFile_config_index!=-1){
			if ( (TSFile_config[TSFile_config_index].state==IOEX_TSFileState_ReceiveFileName) || 
				 (TSFile_config[TSFile_config_index].state==IOEX_TSFileState_ReceiveFileData) ){

 				int dd=strncmp(end_data,header_end_file,4);
				if (dd==0){
					FILE *fptr;        
					fptr=fopen(TSFile_config[TSFile_config_index].filename,"a");
					fwrite(data,1,len-4,fptr);
					fclose(fptr);
					//remove stream
					//sleep(1);					
					callback_func_ReceivedComplete(TSFile_config[TSFile_config_index].filename,TSFile_config
												   [TSFile_config_index].RealFileName);
					usleep(200); 
					IOEX_TSFile_remove_stream(TSFile_config_index);
				}else{
					FILE *fptr;        
					fptr=fopen(TSFile_config[TSFile_config_index].filename,"a");
					fwrite(data,1,len,fptr);
					fclose(fptr);
				}
			}
		}	
	}
}

static void TSFile_request_callback(IOEXCarrier *w, const char *from,
            const char *sdp, size_t len, void *context)
{
	int rc, steam_id;
	IOEXSession *TS_session;
	IOEXStreamState StreamState;
	int state_count;	
	int TSFile_config_index=-1;
	int empty_index=-1;
	int i;

	TS_session=IOEX_session_new(w, from);
	if (!TS_session) {
        vlogE("Create session failed.\n");
		return;
    } 
    usleep(200);

	int options = 0;
	IOEXStreamCallbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.state_changed = SlaveTSFile_stream_on_state_changed;
    callbacks.stream_data = SlaveTSFile_stream_on_data;
    options = IOEX_STREAM_RELIABLE;

	steam_id = IOEX_session_add_stream(TS_session, IOEXStreamType_text,
                                options, &callbacks, NULL);
    state_count=0;
	while (state_count<=Count_WaitStateChange){
    	IOEX_stream_get_state(TS_session,steam_id,&StreamState);
		if (StreamState>=1){
			break;
		}
		usleep(200);
		state_count++;
	}
	if (state_count>=Count_WaitStateChange){
		vlogE("Wait stream state change time out\n");
		return;
	}


	vlogD("[BB]StreamState=%d\n", StreamState);

	for (i=0;i<Max_TSFile_config;i++){
		if (TSFile_config[i].stream==steam_id){
			TSFile_config_index=i;
			break;
		}else
		if (TSFile_config[i].stream==TSFile_NULL_data){
			if (empty_index==-1){
				empty_index=i;
			}
		}
	}
	vlogD("[NN1]TSFile_config_index=%d,empty_index=%d\n", TSFile_config_index,empty_index);	
	if ( (TSFile_config_index==-1) && (empty_index==-1) ){
		vlogE("[Warning]TSFile_config full, no empty\n");
		rc = IOEX_session_reply_request(TS_session, 1, "NoEmpty");
		if (rc < 0) {
			vlogE("IOEX_session_reply_request fail\n");
			return;
		}		
	}

	if (TSFile_config_index==-1){
		if (empty_index!=-1){
			TSFile_config[empty_index].stream=steam_id;			
		}
	}else{
		TSFile_config[TSFile_config_index].stream=steam_id;	
	}
	

    rc = IOEX_session_reply_request(TS_session, 0, NULL);
	if (rc < 0) {
	    vlogE("IOEX_session_reply_request fail\n");
		return;
	}
    
	usleep(2000);
	rc = IOEX_session_start(TS_session, sdp,len);
	if (rc < 0) {
	    vlogE("IOEX_session_start fail\n");
		return;
	}  
}

int IOEX_TSFile_Init(IOEXCarrier *carrier, const char *Path_Savefile){

	int i,size;
	for (i=0;i<Max_TSFile_config;i++)
	{
		TSFile_config[i].ws=0;
		TSFile_config[i].stream=TSFile_NULL_data;
		TSFile_config[i].file_size=TSFile_NULL_data;
		TSFile_config[i].state=IOEX_TSFileState_Nothing;
		TSFile_config[i].start_Position=0;
		strcpy(TSFile_config[i].filename,"");
		strcpy(TSFile_config[i].RealFileName,"");
		strcpy(TSFile_config[i].address,"");
	}	

	size=strlen(Path_Savefile);	
	vlogE("IOEX_session_start size=%d\n",size);
	if (size>Size_Path_SaveFile_Buffer){
		return IOEX_TSFile_ErrorCode_OverBuffer;
	}
	strcpy(Path_SaveReceiveFile,Path_Savefile);

	vlogE("IOEX_session_start size=%d,string=%s\n",size,Path_SaveReceiveFile);
	
	IOEX_session_init(carrier, TSFile_request_callback, NULL);

	return true;
}


int IOEX_TSFile_Request(IOEXCarrier *carrier, const char *address,
						const char* filename, int start_byte){

	int steam_id;
	IOEXSession *TS_session;
	IOEXStreamState StreamState;
	int state_count;	

	int i;
	int TSFile_config_index=-1;
	int empty_index=-1;

	//check file
	FILE *fp=fopen(filename,"r");
	if (fp){
		fclose(fp);
	}else{
		vlogE("File not found\n");
		return IOEX_TSFile_ErrorCode_NoFile;
	}
	//check file

	//check friend
	int rc;
    IOEXFriendInfo fi;
	rc = IOEX_get_friend_info(carrier, address, &fi);
    if (rc < 0) {
        vlogE("Get friend information failed(0x%x).\n", IOEX_get_error());
        return IOEX_TSFile_ErrorCode_GetFriendInfoFail;
    }
	if (fi.status!=IOEXConnectionStatus_Connected){
		vlogE("[Warning]frined:%s is not online\n",address);
		return IOEX_TSFile_ErrorCode_FrinedNotOnLine;
	}
	//check firend	


	TS_session=IOEX_session_new(carrier, address);
    usleep(200);

    int options = 0;
	IOEXStreamCallbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.state_changed = MasterTSFile_stream_on_state_changed;
    callbacks.stream_data = MasterTSFile_stream_on_data;
    options = IOEX_STREAM_RELIABLE;

    steam_id = IOEX_session_add_stream(TS_session, IOEXStreamType_text,
                                options, &callbacks, NULL);
    state_count=0;
	while (state_count<=Count_WaitStateChange){
    	IOEX_stream_get_state(TS_session,steam_id,&StreamState);
		if (StreamState>=1){
			break;
		}
		usleep(200);
		state_count++;
	}
		
    vlogD("[AA]StreamState=%d\n", StreamState);

	//Store data
	//Find a empty TSFile_config
	for (i=0;i<Max_TSFile_config;i++){
		if (TSFile_config[i].stream==steam_id){
			TSFile_config_index=i;
			break;
		}else
		if (TSFile_config[i].stream==TSFile_NULL_data){
			if (empty_index==-1){
				empty_index=i;
			}
		}
	}

	if ( (TSFile_config_index==-1) && (empty_index==-1) ){
		vlogE("[Warning]TSFile_config full, no empty\n");
		return IOEX_TSFile_ErrorCode_NoEmpty;
	}

	if (TSFile_config_index==-1){
		if (empty_index!=-1){
			TSFile_config[empty_index].stream=steam_id;
			strcpy(TSFile_config[empty_index].filename,filename);
			TSFile_config[empty_index].start_Position=start_byte;
			strcpy(TSFile_config[empty_index].address,address);	
		}
	}else{
		TSFile_config[TSFile_config_index].stream=steam_id;
		strcpy(TSFile_config[TSFile_config_index].filename,filename);
		TSFile_config[TSFile_config_index].start_Position=start_byte;
		strcpy(TSFile_config[TSFile_config_index].address,address);	

	}
	vlogD("[bbcc]%d,%d,%d\n", TSFile_config_index,empty_index,TSFile_config[empty_index].stream);
	//Store data

	IOEX_session_request(TS_session,
                             session_request_complete_callback, NULL);
    IOEX_stream_get_state(TS_session,steam_id,&StreamState);
    vlogD("[AA]StreamState=%d\n", StreamState);
	
	vlogD("[AA]steam_id=%d\n", steam_id);
	return IOEX_TSFile_ErrorCode_OK;

}
int IOEX_TSFile_ReceivedComplete_Callback(IOEXCarrier *carrier, ReceivedComplete *callback){

	callback_func_ReceivedComplete=callback;
	return true;
}

