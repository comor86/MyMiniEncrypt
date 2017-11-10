#include <fltKernel.h>
#include <string.h>

/************************************************************************/
/*                     加解密函数  使用RC4算法                           */
/************************************************************************/
//置换s中的两个元素
void swap(unsigned char *s1, unsigned char *s2)
{
	char temp;
	temp = *s1;
	*s1 = *s2;
	*s2 = temp;
}

void re_S(unsigned char *S)
{
	unsigned int i;
	for (i = 0; i<256; i++)
		S[i] = (unsigned char)i;
}
//用密匙key初始化临时变量T
void re_T(char *T, char *key)
{
	int i;
	int keylen;
	keylen = strlen(key);
	for (i = 0; i<256; i++)
		T[i] = key[i%keylen];
}
//用T产生S的初始置换．从S[0]到S[255]，对每个S[i]，根据由T[i]确定的方案，将S[i]置换为S中的另一字节
void re_Sbox(unsigned char *S, char *T)
{
	int i;
	int j = 0;
	for (i = 0; i<256; i++)
	{
		j = (j + S[i] + T[i]) % 256;
		swap(&S[i], &S[j]);//置换
	}
}
//re_RC4()实现S向量的初始化
void re_RC4(unsigned char *S, char *key)
{
	char T[255] = { 0 };
	re_S(S);
	re_T(T, key);
	re_Sbox(S, T);
}
//RC4算法
void RC4(char *inBuf, char *outBuf, LONGLONG offset, ULONG bufLen, char *key)
{
	unsigned char S[255] = { 0 };
	unsigned char readbuf[1];
	int i, j, t;
	LONGLONG z; //i和j用于置换s，t用于获取密匙流，z用于传输加解密内容
	re_RC4(S, key);//调用re_RC4()初始化s
	//fileOffset=fileOffset%256;如果加密密匙流没有周期性这样可能会出错，如果有周期性的话这样效率可提高一点
	i = j = 0;
	z = 0;
	while (z<offset)//偏移量之前的不加密，只是用于生成到偏移量处密匙
	{
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		swap(&S[i], &S[j]);
		z++;
	}
	z = 0;
	while (z<bufLen)
	{
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		swap(&S[i], &S[j]);
		t = (S[i] + (S[j] % 256)) % 256;//生成密匙流的再s中的下标
		readbuf[0] = inBuf[z];
		//将输入缓冲区的一个字节赋值给临时缓冲区    
		readbuf[0] = readbuf[0] ^ S[t];
		outBuf[z] = readbuf[0];
		z++;
	}
}
