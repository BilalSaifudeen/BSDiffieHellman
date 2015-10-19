//
//  MainViewController.m
//  BSDiffieHellman
//
//  Created by Bilal Saifudeen on 10/19/15.
//  Copyright © 2015 Bilal Saifudeen. All rights reserved.
//

#import "MainViewController.h"

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
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)generateTapped:(id)sender {
    //Do Diffie Hellman
    
}

@end
