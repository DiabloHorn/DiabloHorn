/*
DiabloHorn http://diablohorn.wordpress.com
*/
#define _GNU_SOURCE //non posix compliant accepted risk
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>

RSA *RSA_generate_key(int num, unsigned long e, void (*callback)(int,int,void *), void *cb_arg){
    RSA *rsa;
    BIO* rsaPrivateBio;
    typeof(RSA_generate_key) *old_RSA_generate_key;
    
    printf("hooked function: RSA_generate_key\n");
    old_RSA_generate_key = dlsym(RTLD_NEXT, "RSA_generate_key");

    //rsa = (*old_RSA_generate_key)(1024,RSA_F4,NULL,NULL); //the hardcoded example
    rsa = (*old_RSA_generate_key)(num,e,callback,cb_arg); //not sure if this will always work, if not use the hardcoded line
    if(rsa == NULL){
        printf("error in generating keypair..");
        return 0;
    }
    RSA_blinding_on(rsa, NULL);
    rsaPrivateBio = BIO_new_file("rsa.key", "w");
    PEM_write_bio_RSAPrivateKey(rsaPrivateBio, rsa, NULL, NULL, 0, NULL, NULL);
    printf("saved private key to file\n");
    BIO_free(rsaPrivateBio);
    //return the private key we just saved to file
    return rsa;
}
