/********************************Copyright ( c ) ******************************** 
**                             Shenzhen, China 
**                     http://blog.csdn.net/u011502387 
**                         
** 
** Created By:      崔龙龙 
** Created Date:    2017-09-01 
** Description:     C语言实现数据AES加解密 
** Version:         V1.0 
** History:         NULL 
** Declaration:     引用请注明出处，谢谢。 
**  
****************************************************************************/  
#include <stdio.h>
#include "aes.h"

/**************************************************************************** 
Description:            打印标题和字符串(print) 
Input parameters:        
                        const uint8_t *msg:需要打印的标题 
                        const uint8_t *buf:需要打印的字符串 
						const uint8_t Len:需要打印的字符串长度
Output parameters:       
                        NULL
                         
Returned value:      
                        NULL 
Created by:          
                        崔龙龙 (2017-09-01) 
Modified by:             
                        NULL 
****************************************************************************/ 
void print(const uint8_t *msg, const uint8_t *buf, const uint8_t Len)
{
	int i;

	printf("%s", msg);
	for(i=0; i< Len; ++i)
		printf("%02x ", buf[i]);
	printf("\n");
}

/**************************************************************************** 
Description:            
						主函数，测试AES(main)                        
Created by:          
                        崔龙龙 (2017-09-01) 
Modified by:             
                        NULL  
****************************************************************************/ 
int main()
{	
	int i;
	aes_context ctx;
	uint8_t ret_text[16] = {0};
	uint8_t cipher_text[16] = {0};
	uint32_t key_bit[3] = {128, 192, 256};
	uint8_t text[16] = {//明文
		0x0f,0x1e,0x2d,0x3c,
		0x4b,0x5a,0x69,0x78,
		0x87,0x96,0xa5,0xb4,
		0xc3,0xd2,0xe1,0xf0
	};
	uint8_t key[32] = {//测试密钥
		0x01,0x23,0x45,0x67,
		0x89,0xab,0xcd,0xef,
		0xef,0xcd,0xab,0x89,
		0x67,0x45,0x23,0x01,
		0x00,0x11,0x22,0x33,
		0x44,0x55,0x66,0x77,
		0x88,0x99,0xaa,0xbb,
		0xcc,0xdd,0xee,0xff
	};
	
	for (i = 0; i < sizeof(key_bit)/sizeof(key_bit[0]); ++i)
	{
		if (aes_set_key(&ctx, key, key_bit[i]) != SUCCESS)//初始化AES结构体ctx，包括密钥处理
		{
			printf("aes_set_key error.");
			return -1;
		}
		if(aes_encrypt_block(&ctx, cipher_text, text) != SUCCESS)//调用AES加密接口
		{
			printf("aes_encrypt_block error.");
			return -1;
		}
		if(aes_decrypt_block(&ctx, ret_text, cipher_text) != SUCCESS)//调用AES解密接口
		{
			printf("aes_decrypt_block error.");
			return -1;
		}
		printf("key_bit %d: \n", key_bit[i]);
		print("\tkey    :  ", key , 16+8*i);
		print("\tinput  :  ", text ,16);
		print("\tencrypt:  ", cipher_text , 16);
		print("\tdecrypt:  ", ret_text,16);

	}
	return 0;
}
