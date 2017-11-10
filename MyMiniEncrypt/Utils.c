
#include "Utils.h"
#include "rc4.h"
/************************************************************************/
/*读取文件加密信息                                                                     */
/************************************************************************/

#pragma  LOCKEDCODE
NTSTATUS MyGetFileEncryptInfoToCtx(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__inout PSTREAM_HANDLE_CONTEXT ctx)
//	__in PTYPE_KEY_WORD keyWord)
{
	NTSTATUS status;
	ctx->isEncypted = IS_NOT_ENCRYPTED;
	ctx->isEncyptFile = IS_NOT_ENCRYPT_FILE;
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

	BOOLEAN isDir = FALSE;
	BOOLEAN is_encrypt_file = FALSE;

	//检查中断级
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	//判断是否文件夹
	status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDir);

	if (NT_SUCCESS(status))
	{
		//文件夹直接跳过
		if (isDir)
		{
			//DbgPrint("it is a dir");
			return status;
		}
		else
		{
			//获取文件名称
			status = FltGetFileNameInformation(Data,
				FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
				&nameInfo);
			if (NT_SUCCESS(status))
			{
				FltParseFileNameInformation(nameInfo);

				//判断该文件类型是否是加密类型
				//is_encrypt_file = IsInKeyWordList(keyWord,&(nameInfo->Name),&(ctx->keyWord));
				is_encrypt_file = IsInEncryptList(&(nameInfo->Name));

				if (is_encrypt_file)
				{
					DbgPrint("file name is %wZ,",&(nameInfo->Name));
					DbgPrint("is a encrypt file.\n");
					//匹配成功，是加密类型
					ctx->isEncyptFile = IS_ENCRYPT_FILE;

					//读取文件尾部，检测是否已经加密
					CHAR sMark[ENCRYPT_MARK_LEN];
					ULONG readLen = 0;

					//获取文件信息
					FILE_STANDARD_INFORMATION fileInfo;

					status = FltQueryInformationFile(FltObjects->Instance,
						Data->Iopb->TargetFileObject,
						&fileInfo,
						sizeof(FILE_STANDARD_INFORMATION),
						FileStandardInformation, NULL);

					if (NT_SUCCESS(status))
					{

						//获取文件长度
						LONGLONG offset = fileInfo.EndOfFile.QuadPart - ENCRYPT_MARK_LEN;

						if (offset<0)
						{
							ctx->isEncypted = IS_NOT_ENCRYPTED;
						}
						//读取尾部标识
						else
						{
							LARGE_INTEGER l_offset;
							l_offset.QuadPart = offset;
							//读取尾部
							status = FltReadFile(FltObjects->Instance,
								FltObjects->FileObject,
								&(l_offset),
								ENCRYPT_MARK_LEN,
								(PVOID)sMark,
								FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED,
								&readLen, NULL, NULL);

							if (NT_SUCCESS(status))
							{
								//DbgPrint("file trail is %s",trail.mark);
								//DbgPrint("entry string  is %s",ENCRYPT_MARK_STRING);
								//比较标识
								if (strncmp(sMark, ENCRYPT_MARK_STRING, strlen(ENCRYPT_MARK_STRING)) == 0)
								{
									//DbgPrint("file  %wZ trail is encrypten ",&(nameInfo->Name));
									ctx->isEncypted = IS_ENCRYPTED;
								}

							}
							else
							{
								//DbgPrint("read file err when in get file info");
							}
						}

					}

				}
				else
				{
					//DbgPrint("no a filt file");
				}

			}
			else
			{
				//DbgPrint("can not read filename");
			}
		}
	}
	else
	{
		//DbgPrint("test dir fail");
	}

	if (nameInfo != NULL)
	{
		FltReleaseFileNameInformation(nameInfo);
	}

	return status;

}

BOOLEAN IsInEncryptList(PUNICODE_STRING file_name)
{
	if (file_name->Length > 0)	
		return TRUE;

	return FALSE;
}

void cfFileCacheClear(PFILE_OBJECT pFileObject)
{
	PFSRTL_COMMON_FCB_HEADER pFcb;
	LARGE_INTEGER liInterval;
	BOOLEAN bNeedReleaseResource = FALSE;
	BOOLEAN bNeedReleasePagingIoResource = FALSE;
	KIRQL irql;


	pFcb = (PFSRTL_COMMON_FCB_HEADER)pFileObject->FsContext;
	if (pFcb == NULL)
		return;

	irql = KeGetCurrentIrql();
	if (irql >= DISPATCH_LEVEL)
	{
		return;
	}

	liInterval.QuadPart = -1 * (LONGLONG)50;

	while (TRUE)
	{
		BOOLEAN bBreak = TRUE;
		BOOLEAN bLockedResource = FALSE;
		BOOLEAN bLockedPagingIoResource = FALSE;
		bNeedReleaseResource = FALSE;
		bNeedReleasePagingIoResource = FALSE;

		// 到fcb中去拿锁。
		if (pFcb->PagingIoResource)
			bLockedPagingIoResource = ExIsResourceAcquiredExclusiveLite(pFcb->PagingIoResource);

		// 总之一定要拿到这个锁。
		if (pFcb->Resource)
		{
			bLockedResource = TRUE;
			if (ExIsResourceAcquiredExclusiveLite(pFcb->Resource) == FALSE)
			{
				bNeedReleaseResource = TRUE;
				if (bLockedPagingIoResource)
				{
					if (ExAcquireResourceExclusiveLite(pFcb->Resource, FALSE) == FALSE)
					{
						bBreak = FALSE;
						bNeedReleaseResource = FALSE;
						bLockedResource = FALSE;
					}
				}
				else
					ExAcquireResourceExclusiveLite(pFcb->Resource, TRUE);
			}
		}

		if (bLockedPagingIoResource == FALSE)
		{
			if (pFcb->PagingIoResource)
			{
				bLockedPagingIoResource = TRUE;
				bNeedReleasePagingIoResource = TRUE;
				if (bLockedResource)
				{
					if (ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, FALSE) == FALSE)
					{
						bBreak = FALSE;
						bLockedPagingIoResource = FALSE;
						bNeedReleasePagingIoResource = FALSE;
					}
				}
				else
				{
					ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, TRUE);
				}
			}
		}

		if (bBreak)
		{
			break;
		}

		if (bNeedReleasePagingIoResource)
		{
			ExReleaseResourceLite(pFcb->PagingIoResource);
		}
		if (bNeedReleaseResource)
		{
			ExReleaseResourceLite(pFcb->Resource);
		}

		if (irql == PASSIVE_LEVEL)
		{
			KeDelayExecutionThread(KernelMode, FALSE, &liInterval);
		}
		else
		{
			KEVENT waitEvent;
			KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);
			KeWaitForSingleObject(&waitEvent, Executive, KernelMode, FALSE, &liInterval);
		}
	}

	if (pFileObject->SectionObjectPointer)
	{
		IO_STATUS_BLOCK ioStatus;
		CcFlushCache(pFileObject->SectionObjectPointer, NULL, 0, &ioStatus);

		if (NT_SUCCESS(ioStatus.Status))
		{
			//KdPrint(("CcFlushCache OK\n"));
		}
		else
		{
			//KdPrint(("CcFlushCache Failed\n"));
		}

		if (pFileObject->SectionObjectPointer->ImageSectionObject)
		{
			//MmFlushImageSection(pFileObject->SectionObjectPointer,MmFlushForWrite); // MmFlushForDelete


			if (MmFlushImageSection(pFileObject->SectionObjectPointer, MmFlushForWrite) == TRUE)
			{
				//KdPrint(("MmFlushImageSection OK\n"));
			}
			else
			{
				//KdPrint(("MmFlushImageSection Failed\n"));
			}
		}
		//CcPurgeCacheSection(pFileObject->SectionObjectPointer, NULL, 0, FALSE);

		if (CcPurgeCacheSection(pFileObject->SectionObjectPointer, NULL, 0, TRUE) == TRUE)
		{
			//KdPrint(("CcPurgeCacheSection OK\n"));
		}
		else
		{
			//KdPrint(("CcPurgeCacheSection Failed\n"));
		}

		///
		{
			KEVENT waitEvent1;
			LARGE_INTEGER liInterval0;
			liInterval0.QuadPart = 0;
			KeInitializeEvent(&waitEvent1, NotificationEvent, FALSE);
			CcUninitializeCacheMap(pFileObject, &liInterval0, (PCACHE_UNINITIALIZE_EVENT)&waitEvent1);
			KeWaitForSingleObject(&waitEvent1, Executive, KernelMode, FALSE, &liInterval0);
		}

		//CcSetFileSizes(pFileObject,0);
	}

	if (bNeedReleasePagingIoResource)
	{
		ExReleaseResourceLite(pFcb->PagingIoResource);
	}
	if (bNeedReleaseResource)
	{
		ExReleaseResourceLite(pFcb->Resource);
	}
}

NTSTATUS
EncryptFile(__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__in PCHAR key)
{
	NTSTATUS status;

	FILE_STANDARD_INFORMATION fileInfo;
	ULONG len = 0;

	//检查中断级
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	//获取文件信息
	status = FltQueryInformationFile(FltObjects->Instance,
		FltObjects->FileObject,
		&fileInfo,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation, &len);

	if (NT_SUCCESS(status))
	{

		//获取文件长度
		LONGLONG fileLen = fileInfo.EndOfFile.QuadPart;
		ULONG buffLen = 1024 * 1024;
		ULONG writeLen;
		ULONG readLen;
		LARGE_INTEGER offset;
		offset.QuadPart = 0;


		//申请缓冲区
		PVOID buff = ExAllocatePoolWithTag(NonPagedPool,
			buffLen,
			BUFFER_SWAP_TAG);
		if (buff == NULL)
		{
			DbgPrint("no enough memoy");
			return STATUS_UNSUCCESSFUL;
		}

		PMDL newMdl = IoAllocateMdl(buff,
			buffLen,
			FALSE,
			FALSE,
			NULL);

		if (newMdl != NULL) {
			MmBuildMdlForNonPagedPool(newMdl);
		}

		RtlZeroMemory(buff, buffLen);

		//加密原文件//////////////////////////////
		LONGLONG hadWrite = 0;
		while (hadWrite<fileLen)
		{
			//读取文件
			status = FltReadFile(FltObjects->Instance,
				FltObjects->FileObject,
				&offset,
				buffLen,
				buff,
				FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED,
				&readLen, NULL, NULL);
			if (!NT_SUCCESS(status))
			{
				DbgPrint("read file err when move file content");
				ExFreePool(buff);
				if (newMdl != NULL) {

					IoFreeMdl(newMdl);
				}
				return status;
			}

			//加密缓冲区
//			EncryptData(buff, buff, offset.QuadPart, readLen, key);
			//写入文件
			status = FltWriteFile(FltObjects->Instance,
				FltObjects->FileObject,
				&offset,
				readLen,
				buff,
				0,
				&writeLen,
				NULL,
				NULL
				);
			if (readLen != writeLen)
			{
				DbgPrint("write len not equal the read len");
			}
			if (!NT_SUCCESS(status))
			{
				DbgPrint("write file err when move file content");
				ExFreePool(buff);
				if (newMdl != NULL) {

					IoFreeMdl(newMdl);
				}
				return status;
			}
			//
			offset.QuadPart += readLen;
			hadWrite += readLen;
		}

		//写入加密尾///////////////////////////////
		offset = fileInfo.EndOfFile;
		RtlZeroMemory(buff, buffLen);
		RtlCopyMemory(buff, ENCRYPT_MARK_STRING, strlen(ENCRYPT_MARK_STRING));

		//DbgPrint("buff is %s",buff);

		status = FltWriteFile(FltObjects->Instance,
			FltObjects->FileObject,
			&offset,
			ENCRYPT_MARK_LEN,
			buff,
			0,
			&writeLen,
			NULL,
			NULL
			);

		if (!NT_SUCCESS(status))
		{
			DbgPrint("encypt file wrong when write");
			ExFreePool(buff);
			if (newMdl != NULL) {

				IoFreeMdl(newMdl);
			}
			return status;
		}

		//释放资源
		ExFreePool(buff);
		if (newMdl != NULL) {

			IoFreeMdl(newMdl);
		}
		return status;
	}
	return status;
}


/************************************************************************/
/*    获取进程名称偏移                                                 */
/************************************************************************/
//////////////////////////////////////////////////////////////////////////
//获取进程名称

//----------------------------------------------------------------------
//
// GetProcessNameOffset
//
// In an effort to remain version-independent, rather than using a
// hard-coded into the KPEB (Kernel Process Environment Block), we
// scan the KPEB looking for the name, which should match that
// of the GUI process
//
//----------------------------------------------------------------------

ULONG
GetProcessNameOffset(
VOID
)
{
	PEPROCESS       curproc;
	int             i;

	curproc = PsGetCurrentProcess();

	//
	// Scan for 12KB, hopping the KPEB never grows that big!
	//
	for (i = 0; i < 3 * PAGE_SIZE; i++) {

		if (!strncmp("System", (PCHAR)curproc + i, strlen("System"))) {

			return i;
		}
	}

	//
	// Name not found - oh, well
	//
	return 0;
}



PCHAR
GetCurrentProcessName(ULONG ProcessNameOffset)
{
	PEPROCESS       curproc;
	char            *nameptr;
	ULONG           i;

	//
	// We only try and get the name if we located the name offset
	//
	if (ProcessNameOffset) {

		//
		// Get a pointer to the current process block
		//
		curproc = PsGetCurrentProcess();

		//
		// Dig into it to extract the name. Make sure to leave enough room
		// in the buffer for the appended process ID.
		//
		nameptr = (PCHAR)curproc + ProcessNameOffset;
		/*
		#if defined(_M_IA64)
		sprintf( szName + strlen(szName), ":%I64d", PsGetCurrentProcessId());
		#else
		sprintf( szName + strlen(szName), ":%d", (ULONG) PsGetCurrentProcessId());
		#endif
		//*/

	}
	else {

		nameptr = "";
	}
	return nameptr;
}



/************************************************************************/
/* 加密函数   buff:输入的缓冲区，outbuff：输出缓冲区 offset:流偏移  len：缓冲区长度  key:密匙                                                                */
/************************************************************************/
void EncryptData(__in PVOID buff, __in PVOID outbuff, __in LONGLONG offset, __in ULONG len, PCHAR key)
{
	//RC4加密
	char * indata = (char *)buff;
	char * outdata = (char *)outbuff;


	RC4(indata, outdata, offset, len, key);
	//XOR(indata,outdata,len,key);
}

/************************************************************************/
/* 解密函数   buff:输入的缓冲区，output：输出缓冲区 offset:流偏移 len：缓冲区长度  key:密匙                                                                  */
/************************************************************************/
void DecodeData(__in PVOID buff, __in PVOID outbuff, __in LONGLONG offset, __in ULONG len, PCHAR key)
{
	//RC4解密
	char * indata = (char *)buff;
	char * outdata = (char *)outbuff;


	RC4(indata, outdata, offset, len, key);
	//XOR(indata,outdata,len,key);
}