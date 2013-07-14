/*
DiabloHorn http://diablohorn.wordpress.com
Based on:
    http://sudhirmurthy.blogspot.nl/2008/06/generating-rsa-key-pair.html
    http://openssl.6102.n7.nabble.com/RSA-public-private-keys-only-work-when-created-programatically-td12532.html
*/
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <stdlib.h>
#include <stdio.h>

int main(){
    RSA *rsa;
    BIO* rsaPrivateBio;

    rsa = RSA_generate_key(1024,RSA_F4,NULL,NULL);
    if(rsa == NULL){
        printf("error in generating keypair..");
        return 0;
    }
    RSA_blinding_on(rsa, NULL);
    rsaPrivateBio = BIO_new_file("rsa.key", "w");
    PEM_write_bio_RSAPrivateKey(rsaPrivateBio, rsa, NULL, NULL, 0, NULL, NULL);
    
    BIO_free(rsaPrivateBio);
    RSA_free(rsa);
    return 0;
}
