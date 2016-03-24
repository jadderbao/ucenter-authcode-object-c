//
//  DiscuzAuthentic.h
//  TestDiscuzAuth
//
//  Created by jad on 15/9/9.
//  jadderbao@163.com
//  Copyright (c) 2015. All rights reserved.
//

#import <Foundation/Foundation.h>

enum {
    DiscuzAuthentecEncode = 0,		/* 0..127 only */
    DiscuzAuthentecDecode = 1		/* 0..127 only */
};

typedef NSUInteger DiscuzAuthcodeMode;

@interface DiscuzAuthentic : NSObject

+(NSString *)cutString:(NSString *)str :(int)start :(int)length;
+(long) getUnixTimestamp;
+(NSString *)randomString:(int)length;
+(NSString *)authcodeEncode:(NSString *)source :(NSString *)key;
+(NSString *)authcodeDecode:(NSString *)source :(NSString *)key;
+(NSString *)authcode:(NSString *)source :(NSString *)key :(DiscuzAuthcodeMode)operation :(int)expiry;

@end
