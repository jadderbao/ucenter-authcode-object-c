//
//  DiscuzAuthentic.m
//  TestDiscuzAuth
//
//  Created by jad on 15/9/9.
//  jadderbao@163.com
//  Copyright (c) 2015. All rights reserved.
//

#import "DiscuzAuthentic.h"
#import <CommonCrypto/CommonDigest.h>
#import "GTMBase64.h"

@implementation DiscuzAuthentic

+(NSString *)cutString:(NSString *)str :(int)start :(int)length;
{
    if (start >= 0) {
        if (length < 0) {
            length = length * -1;
            if (start - length < 0) {
                length = start;
                start  = 0;
            } else {
                start = start - length;
            }
        }
        
        if (start > str.length) {
            return @"";
        }
    } else {
        if (length < 0) {
            return @"";
        } else {
            if (length + start > 0) {
                length = length + start;
                start = 0;
            } else {
                return @"";
            }
        }
    }
    
    if (str.length - start < length) {
        length = (int)str.length  - start;
    }
    
    return [str substringWithRange:NSMakeRange(start, length)];
}

// / <summary>
// / 从字符串的指定位置开始截取到字符串结尾的了符串
// / </summary>
// / <param name="str">原字符串</param>
// / <param name="startIndex">子字符串的起始位置</param>
// / <returns>子字符串</returns>
+ (NSString *)cutString:(NSString *)str :(int)startIndex
{
    return [self cutString:str :startIndex :(int)str.length];
}

+(NSString *)randomString:(int)length
{
    NSString *randomStr = @"abcdefghijklmnopqrstuvwxyz0123456789";
    int clens = (int)randomStr.length;
    
    NSMutableString *code = [NSMutableString stringWithString:@""];
    srand(length);
    for (int i = 0; i < length; i++) {
        NSString *subStr = [randomStr substringWithRange:NSMakeRange(rand() % clens, 1)];
        [code appendString:subStr];
    }
    
    return code;
}

+(NSData *) getKey:(Byte *)pass :(int)passLen :(int)kLen
{
    Byte *mBox = malloc(kLen);
    for (int i = 0; i < kLen; i++) {
        mBox[i] = i;
    }
    
    int j = 0;
    for (int i = 0; i < kLen; i++) {
        
        j = (j + (int) ((mBox[i] + 256) % 256) + pass[i % passLen]) % kLen;
        
        Byte temp = mBox[i];
        mBox[i] = mBox[j];
        mBox[j] = temp;
    }
    
    return [NSData dataWithBytesNoCopy:mBox length:kLen];
}

// / <summary>
// / RC4 原始算法
// / </summary>
// / <param name="input">原始字串数组</param>
// / <param name="pass">密钥</param>
// / <returns>处理后的字串数组</returns>

+(NSData *) RC4:(Byte *)data :(int)dataLen :(Byte *)pass :(int)passLen {
    
    if (data == nil || pass == nil)
        return nil;
    
    Byte* output = malloc(dataLen);
    NSData* mBoxData = [self getKey:pass :passLen :256];
    
    unsigned long mBoxLen = mBoxData.length;
    Byte *mBox = malloc(mBoxLen);
    [mBoxData getBytes:mBox length:mBoxLen];
    
    // 加密
    int i = 0;
    int j = 0;
    
    for (int offset = 0; offset < dataLen; offset++) {
        i = (i + 1) % mBoxLen;
        j = (j + (int) ((mBox[i] + 256) % 256)) % mBoxLen;
        
        Byte temp = mBox[i];
        mBox[i] = mBox[j];
        mBox[j] = temp;
        Byte a = data[offset];
        
        // byte b = mBox[(mBox[i] + mBox[j] % mBox.Length) % mBox.Length];
        // mBox[j] 一定比 mBox.Length 小，不需要在取模
        Byte b = mBox[([self toInt:mBox[i]] + [self toInt:mBox[j]]) % mBoxLen];
        
        output[offset] = (Byte) ((int) a ^ [self toInt:b]);
    }
    
    return [NSData dataWithBytesNoCopy:output length:dataLen];
}

+(NSData *) RC4:(NSData *)data :(NSData *)pass
{
    return [self RC4:(Byte *)[data bytes] :(int)[data length] :(Byte *)[pass bytes] :(int)[pass length]];
}


+(int)toInt :(Byte) b
{
    return (int) ((b + 256) % 256);
}

+(long) getUnixTimestamp
{
   return [[NSDate date] timeIntervalSince1970] * 1000;
}

+(NSString *) md5:(NSString *)data
{
    const char *original_str = [data UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    
    CC_MD5(original_str, (CC_LONG)strlen(original_str), result);
    
    NSMutableString *hash = [NSMutableString string];
    for (int i = 0; i < 16; i++){
        [hash appendFormat:@"%.2X", result[i]];
    }
    
    return [hash lowercaseString];
}


+(NSString *)authcodeEncode:(NSString *)source :(NSString *)key
{
    return [self authcode:source :key :DiscuzAuthentecEncode :0];
}

+(NSString *)authcodeDecode:(NSString *)source :(NSString *)key
{
    return [self authcode:source :key :DiscuzAuthentecDecode :0];
}

+(BOOL)isValidAuthResult:(NSString*)result :(NSString*)keyb
{
    return [[self cutString:result :10 :16] isEqualToString:
            [self cutString:[self md5:[NSString stringWithFormat:@"%@%@", [self cutString:result :26], keyb]]  :0 :16]];
}

+(NSString *)authcode:(NSString *)source :(NSString *)key :(DiscuzAuthcodeMode)operation :(int)expiry
{
    if (source == nil || key == nil) {
        return @"";
    }
    
    int ckey_length = 4;
    
    key = [self md5:key];
    
    NSString *cutStr = [self cutString:key :0 :16];
    NSString *keya = [self md5:cutStr];
    cutStr = [self cutString:key :16 :16];
    NSString *keyb = [self md5:cutStr];
    NSString *keyc = @"";
    if (ckey_length > 0) {
        keyc = (operation == DiscuzAuthentecDecode) ? [self cutString:source :0 :ckey_length ] : [self randomString:ckey_length];
    }
    
    NSString *crypkey = [NSString stringWithFormat:@"%@%@", keya, [self md5:[NSString stringWithFormat:@"%@%@", keya, keyc]]];
    
    NSData *crykeyData = [crypkey dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
    
    NSString *result = nil;
    
    if (operation == DiscuzAuthentecDecode) {
        
        NSData* temp = [self decodeBase64StringToData:[self cutString:source :ckey_length]];
        
        temp = [self RC4:temp :crykeyData];
        
        result =  [[NSString alloc] initWithData:temp encoding:NSUTF8StringEncoding];
        
        if ([self isValidAuthResult:result :keyb]) {
            return [self cutString:result :26];
        } else {
            
            temp = [self decodeBase64StringToData:[self cutString:[NSString stringWithFormat:@"%@=", source] :ckey_length]];
            
            temp = [self RC4:temp :crykeyData];
            
            result =  [[NSString alloc] initWithData:temp encoding:NSUTF8StringEncoding];
            if ([self isValidAuthResult:result :keyb]) {
        
                return [self cutString:result :26];
            } else {
                temp = [self decodeBase64StringToData:[self cutString:[NSString stringWithFormat:@"%@==", source] :ckey_length]];
                temp = [self RC4:temp :crykeyData];
                result =  [[NSString alloc] initWithData:temp encoding:NSUTF8StringEncoding];
                if ([self isValidAuthResult:result :keyb]) {
                    
                    return [self cutString:result :26];
                    
                } else {
                    return @"2";
                }
            }
        }
        
    } else {
        
        source = [NSString stringWithFormat:@"0000000000%@%@", [self cutString:[self md5:[NSString stringWithFormat:@"%@%@", source , keyb]]  :0 :16], source];
        
        NSData *temp = [source dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
        temp = [self RC4:temp :crykeyData];
        
        return [NSString stringWithFormat:@"%@%@", keyc, [self encodeBase64Data:temp]];
    }
    
   return @"";
}


+ (NSString*)encodeBase64String:(NSString * )input {
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
    data = [GTMBase64 encodeData:data];
    NSString *base64String = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return base64String;
}

+ (NSData*)encodeBase64StringToData:(NSString * )input {
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
    return [GTMBase64 encodeData:data];
}

+ (NSString*)decodeBase64String:(NSString * )input {
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
    data = [GTMBase64 decodeData:data];
    NSString *base64String = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return base64String;
}

+ (NSData*)decodeBase64StringToData:(NSString * )input {
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
    return [GTMBase64 decodeData:data];
}

+ (NSString*)encodeBase64Data:(NSData *)data {
    data = [GTMBase64 encodeData:data];
    NSString *base64String = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return base64String;
}

+ (NSString*)decodeBase64Data:(NSData *)data {
    data = [GTMBase64 decodeData:data];
    NSString *base64String = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return base64String;
}


@end
