
#ifndef __MINIFILTER_ENCRYPT_H__
#define __MINIFILTER_ENCRYPT_H__


#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

/*************************************************************************
Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
_In_ PDRIVER_OBJECT DriverObject,
_In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
MyMiniEncryptInstanceSetup(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
_In_ DEVICE_TYPE VolumeDeviceType,
_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
MyMiniEncryptInstanceTeardownStart(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
MyMiniEncryptInstanceTeardownComplete(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
MyMiniEncryptUnload(
_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
MyMiniEncryptInstanceQueryTeardown(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
MyMiniEncryptPreOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

VOID
MyMiniEncryptOperationStatusCallback(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
_In_ NTSTATUS OperationStatus,
_In_ PVOID RequesterContext
);

FLT_POSTOP_CALLBACK_STATUS
MyMiniEncryptPostOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
MyMiniEncryptPreOperationNoPostOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

BOOLEAN
MyMiniEncryptDoRequestOperationStatus(
_In_ PFLT_CALLBACK_DATA Data
);

//
// 自定义回调函数声明
//
FLT_PREOP_CALLBACK_STATUS
MyPreCreate(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
MyPostCreate(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
MyPreRead(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
MyPostRead(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
MyPreWrite(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
MyPostWrite(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
MyPreClose(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
MyPostClose(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
MyPreQueryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
MyPostQueryInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
MyPreSetInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
MyPostSetInformation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
);

#define IS_ENCRYPT_FILE 0x01
#define IS_NOT_ENCRYPT_FILE 0x00

#define IS_ENCRYPTED 0x01
#define IS_NOT_ENCRYPTED 0x00

//定义文件加密标识
//加密标识字符
#define  ENCRYPT_MARK_STRING "*****this file has been encypted*****"

//标识长度
#define  ENCRYPT_MARK_LEN 128

//加密文件内容偏移
#define  ENCRYPT_FILE_CONTENT_OFFSET 128

//定义密匙最大长度
#define		KEY_MAX_LEN		32

#define BUFFER_SWAP_TAG     'swTg'
#define PRE_2_POST_TAG      'pptg'

//定义流上下文信息
typedef struct _STREAM_HANDLE_CONTEXT{

	FILE_STANDARD_INFORMATION fileInfo;//文件信息
//	PTYPE_KEY_WORD keyWord;//文件类型
	INT isEncyptFile;//是否加密文件
	INT isEncypted;//是否已经加密

} STREAM_HANDLE_CONTEXT, *PSTREAM_HANDLE_CONTEXT;

//
// 这是一个自定义上下文结构体，用来将信息从pre操作传递到post操作
//
typedef struct _PRE_2_POST_CONTEXT {

	BOOLEAN IS_ENCODED;
	PVOID SwappedBuffer;

} PRE_2_POST_CONTEXT, *PPRE_2_POST_CONTEXT;

#endif