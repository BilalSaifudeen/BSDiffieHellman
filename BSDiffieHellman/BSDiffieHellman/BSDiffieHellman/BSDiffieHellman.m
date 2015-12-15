//
//  BSDiffieHellman.m
//  BSDiffieHellman
//
//  Created by Bilal Saifudeen on 15/12/15.
//  Copyright © 2015 Bilal Saifudeen. All rights reserved.
//

#import "BSDiffieHellman.h"

#import <openssl/dh.h>
#import <openssl/err.h>
#import <openssl/ssl.h>

@interface BSDiffieHellman ()
{
    DH *dh;
}

@property (nonatomic, assign) int primeLength;

@end

@implementation BSDiffieHellman

#pragma mark - Life Cycle methods

- (instancetype)init{
    return [self initWithPrime:nil andGenerator:nil];
}

- (instancetype)initWithPrimeLength:(int)primeLength{
    if (self = [super init]) {
        self.primeLength = primeLength;
    
        [self initialize];
    }
    return self;
}

- (instancetype)initWithPrime:(NSString *)prime andGenerator:(NSString *)generator{
    if (self = [super init]) {
        [self initialize];
        
        if (prime && generator) {
            [self setPrime:prime andGenerator:generator];
        }
    }
    return self;
}

- (void)initialize{
    dh = DH_new();
}

- (void)dispose{
    DH_free(dh);
}

- (void)dealloc{
    [self dispose];
}

#pragma mark - Diffie Hellman methods

- (void)initializePG{
    NSAssert(self.primeLength != 0, @"Prime Length should not be zero");
    //Create Prime number P and G
    DH_generate_parameters_ex(dh, self.primeLength, DH_GENERATOR_2, NULL);
}


- (void)setPrime:(NSString *)prime andGenerator:(NSString *)generator{
    
    NSParameterAssert(prime);
    NSParameterAssert(generator);
    
    BIGNUM *p = bigNumberFromDecimalString(prime);
    dh->p = p;
    
    BIGNUM *g = bigNumberFromDecimalString(generator);
    dh->g = g;
    
    int codes; //This will be a Bit Masked integer after the check
    int valid = DH_check(dh, &codes);
    
    if (valid != 1) {
        
        NSString *message;
        if (codes & DH_CHECK_P_NOT_PRIME) {
            message = @"DH_CHECK_P_NOT_PRIME";
        }else if (codes & DH_CHECK_P_NOT_SAFE_PRIME){
            message = @"DH_CHECK_P_NOT_SAFE_PRIME";
        }else if (codes & DH_UNABLE_TO_CHECK_GENERATOR){
            message = @"DH_UNABLE_TO_CHECK_GENERATOR";
        }else if (codes & DH_NOT_SUITABLE_GENERATOR){
            message = @"DH_NOT_SUITABLE_GENERATOR";
        }
        
        NSString *failure = [NSString stringWithFormat:@"Prime and generator cannot be set, %@", message];
        NSAssert(valid, failure);
    }
    
}

- (BOOL)generateKeyPairs{
    return (DH_generate_key(dh) == 1);
}

- (NSData *)computeSharedSecretKeyWithOtherPartyPublicKey:(NSData *)otherPartyKey error:(NSError **)error{
    
    BIGNUM *pub_key = bigNumberFromData(otherPartyKey);
    
    //Dynamically allocate required bytes
    unsigned char *computedKey = malloc(DH_size(dh));
    int size = DH_compute_key(computedKey, pub_key, dh);
    
    if (size  == -1) {
        unsigned long errorCode = ERR_get_error();
        
        SSL_load_error_strings();
        
        char errorString[1000];
        char *errorStringDetail = ERR_error_string(errorCode, errorString);
        
        NSString *message = [NSString stringWithCString:errorStringDetail encoding:NSASCIIStringEncoding];
        if (error != NULL) {
            //TODO : Fix the error getting Nil
            *error = [NSError errorWithDomain:@"DiffieHellman" code:1002 userInfo:@{NSLocalizedDescriptionKey : message}];
        }
        return nil;
    }
    
    NSData* computedSecretKey = [[NSData alloc] initWithBytesNoCopy:computedKey length:size freeWhenDone:YES];
    
    return computedSecretKey;
}

#pragma mark - Getter methods

- (NSString *)primeNumber{
    return decimalStringFromBigNumber(dh->p);
}

- (NSString *)generator{
    return decimalStringFromBigNumber(dh->g);
}

- (NSData *)publicKey{
    return dataFromBigNumber(dh->pub_key);
}

- (NSData *)privateKey{
    return dataFromBigNumber(dh->priv_key);
}

#pragma mark - BIGNUM conversions

BIGNUM * bigNumberFromDecimalString(NSString *string){
    const char *cString = [string cStringUsingEncoding:NSASCIIStringEncoding];
    
    BIGNUM *bn = BN_new();
    BN_dec2bn(&bn, cString);
    return bn;
}

NSString * decimalStringFromBigNumber(BIGNUM *bn){
    char *prime  = BN_bn2dec(bn);
    NSString *string = [[NSString alloc] initWithCString:prime encoding:NSASCIIStringEncoding];
    return string;
}

NSData * dataFromBigNumber(BIGNUM *bn){
    
    
    unsigned char *sBuffer;
    
    NSUInteger aLength = BN_num_bytes(bn);
    
    sBuffer = calloc(1, aLength);
    BN_bn2bin(bn, sBuffer);
    
    return [NSData dataWithBytesNoCopy:sBuffer length:aLength freeWhenDone:YES];
}

BIGNUM * bigNumberFromData(NSData *data){
    return BN_bin2bn(data.bytes, (int)data.length, NULL);
}

@end
