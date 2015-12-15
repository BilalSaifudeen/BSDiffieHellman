//
//  MainViewController.m
//  BSDiffieHellman
//
//  Created by Bilal Saifudeen on 10/19/15.
//  Copyright © 2015 Bilal Saifudeen. All rights reserved.
//

#import "MainViewController.h"

#import "BSDiffieHellman.h"

@interface MainViewController ()
@property (weak, nonatomic) IBOutlet UILabel *primeNumberLabel;
@property (weak, nonatomic) IBOutlet UILabel *generatorLabel;

@property (weak, nonatomic) IBOutlet UILabel *bobPrivateKeyLabel;
@property (weak, nonatomic) IBOutlet UILabel *bobPublicKeyLabel;

@property (weak, nonatomic) IBOutlet UILabel *alicePrivateKeyLabel;
@property (weak, nonatomic) IBOutlet UILabel *alicePublicKeyLabel;

@property (weak, nonatomic) IBOutlet UILabel *sharedSecretKeyLabel;

@end

@implementation MainViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    
    
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"Compute Secret" style:UIBarButtonItemStyleDone target:self action:@selector(generateTapped:)];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)generateTapped:(id)sender {

    //Imagine bobDH as server and aliceDH as client
    BSDiffieHellman *bobDH = [[BSDiffieHellman alloc] initWithPrimeLength:256];
    
    //Initializes Prime and generator
    //Can be done in either of the parties(Server or Client)
    //Usually done in server side as it requires heavy computation with higher number of bits like 1024, 2048
    [bobDH initializePG];
    [bobDH generateKeyPairs];
    
    
    BSDiffieHellman *aliceDH = [[BSDiffieHellman alloc] init];
    [aliceDH setPrime:bobDH.primeNumber andGenerator:bobDH.generator];
    
    [aliceDH generateKeyPairs];
    
    NSError *errorComputation1;
    NSError *errorComputation2;
    NSData *computedKeyByAlice =  [aliceDH computeSharedSecretKeyWithOtherPartyPublicKey:bobDH.publicKey error:&errorComputation1];
    NSData *computedKeyByBob =  [bobDH computeSharedSecretKeyWithOtherPartyPublicKey:aliceDH.publicKey error:&errorComputation2];
    
    //Display in UI
    self.primeNumberLabel.text = bobDH.primeNumber;
    self.generatorLabel.text = bobDH.generator;
    
    //Display Bob's Keypairs
    self.bobPrivateKeyLabel.text = [bobDH.privateKey base64EncodedStringWithOptions:0];
    self.bobPublicKeyLabel.text = [bobDH.publicKey base64EncodedStringWithOptions:0];
    
    //Display Alice's Keypairs
    self.alicePrivateKeyLabel.text = [aliceDH.privateKey base64EncodedStringWithOptions:0];
    self.alicePublicKeyLabel.text = [aliceDH.publicKey base64EncodedStringWithOptions:0];
    
    //Computed Key in both ends will be same
    self.sharedSecretKeyLabel.text = [computedKeyByBob base64EncodedStringWithOptions:0];
    
    if ([computedKeyByAlice isEqualToData:computedKeyByBob]) {
        NSLog(@"Success!!! Computed Secret key in both ends are SAME");
    }else{
        NSLog(@"Error!!! Computed Secret key in both ends are Different");
    }
}

@end
