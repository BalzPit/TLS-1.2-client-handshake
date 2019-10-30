#include<stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/err.h>

/*
   ===================================================================
   ======================= S T R U C T U R E S =======================
   ===================================================================
 */


struct tls_record_header{
   unsigned char record_type;
   unsigned char ver[2];
   unsigned char length[2];          //length of the record, excluding the header itself
   unsigned char payload[1];
};

struct handshake_header{           //each handshake message starts with a type and length
   unsigned char type;
   unsigned char length[3];
   unsigned char message[1];
};


struct client_hello{
   unsigned short legacy_ver;
   unsigned char random[32];
   unsigned char id_length;
   unsigned char cipher_length[2];
   unsigned char cipher_suites[2];
   unsigned char compression_length;
   unsigned char legacy_compression_methods;  // exactly one byte set to zero
   unsigned char ext_totlen[2];
   
   //signature algorithms
   unsigned char sa_id[2];
   unsigned char sa_len[2];
   unsigned char sa_list[2];
   unsigned char signature_algorithms[2];
   
   //supported groups
   unsigned char sg_id[2];
   unsigned char sg_len[2];
   unsigned char sg_list[2];
   unsigned char supported_groups[2];

};    

struct server_hello{
   unsigned short server_ver;
   unsigned char random[32];
   unsigned char id_len;       
   unsigned char id[32];   
   unsigned char cipher_suite[2];
   unsigned char compression_method;
};

struct key_exchange{
   unsigned char curve_type;
   unsigned char curve_id[2];
   unsigned char key_len;
   unsigned char key[1];
};



/*
   ===================================================================
   =================  U T I L I T Y   M E T H O D S  =================
   ===================================================================
 */

unsigned short int checksum(char *b, int l) {
   unsigned short *p ;
   int i;
   unsigned short int tot=0;
   unsigned short int prec;
   /*Assunzione: l pari */
   p=(unsigned short *)b;

   for(i=0; i < l/2 ;i++){
      prec = tot;
      tot += htons(p[i]);
      if (tot<prec) tot=tot+1;	
   }
   return (0xFFFF-tot);
}



void stampa_buffer( unsigned char* b, int quanti){
   int i;
   for(i=0;i<quanti;i++){
      printf("%.3d(%.2x) ",b[i],b[i]);
      if((i%4)==3 || i==(quanti-1)){
         printf("\n");
      }
   }
}


/*
   metodo utlizzato per scrivere nel buffer un messaggio di clienthello valido da inviare al server
 */
void clientHello(struct tls_record_header* tls, struct handshake_header * hh, struct client_hello * ch, unsigned char* clientrandom) {
   int i;
   time_t seconds;

   //record header
   tls->record_type = 0x16;  //handshake message
   tls->ver[0] = 0x03;
   tls->ver[1] = 0x01;    // TLS 1.0
   tls->length[1] = 63;

   //handshake header
   hh->type = 0x01;   //clienthello
   hh->length[2] = 59;

   //clienthello
   ch->legacy_ver = htons(0x0303);   // tls 1.2

   //4 byte di gmt_unix_time
   seconds = time(NULL);
   ch->random[0] = seconds;
   ch->random[1] = *(((unsigned char *) &seconds)+1);
   ch->random[2] = *(((unsigned char *) &seconds)+2);
   ch->random[3] = *(((unsigned char *) &seconds)+3);
   //28 random bytes
   for (i=0; i<28; i++){
      ch->random[i+4] = (unsigned char) rand();
   }

   //save client random
   memcpy(clientrandom, ch->random, 32);

   ch->id_length = 0;
   ch->cipher_length[1] = 2;
   ch->cipher_suites[0] = 0xc0;
   ch->cipher_suites[1] = 0x2f;   
   // 0xc02f-> TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
   // Protocol: TLS
   // Key Exchange: Elliptic Curve Diffie-Hellmann Ephemeral (ECDHE)
   // Authentication: Rivest Shamir Adleman algorithm (RSA)
   // Hash: Secure Hash Algorithm 256 (SHA256) 
   ch->compression_length = 1;
   ch->legacy_compression_methods = 0;

   //extensions
   ch->ext_totlen[1] = 16;

   ch->sa_id[1] = 13;  //supported signature algorithms(this can influence the cerificate presented by the sever)
   ch->sa_len[1] = 4;
   ch->sa_list[1] = 2;
   ch->signature_algorithms[0] = 0x04;
   ch->signature_algorithms[1] = 0x01;  // 0x0401 = RSA_PKCS1_SHA256
   //ch->signature_algorithms[1] = 0x03;  // 0x0403 = ECDSA_SECP256r1_SHA256

   ch->sg_id[1] = 10;  //supported groups (elliptic curve(s))
   ch->sg_len[1] = 4;
   ch->sg_list[1] = 2;
   //ch->supported_groups[1] = 0x1d;  // x25519 elliptic curve
   ch->supported_groups[1] = 0x17;   //secp256r1 / x9.62 prime256v1 elliptic curve

}


/*
   this message is used to send the client's public key to the server
   */
void clientKeyExchange(struct tls_record_header* tls, struct handshake_header * hh, unsigned char* client_public_key) {

   //record header
   tls->record_type = 0x16;  //handshake message
   tls->ver[0] = 0x03;
   tls->ver[1] = 0x03;    // TLS 1.0
   tls->length[1] = 37;

   //handshake header
   hh->type = 0x10;   //clientKeyExchange
   hh->length[2] = 33;

   //key exchange message
   unsigned char *key = hh->message;

   //indicate key length
   //key = 32;

   //copy key on buffer
   memcpy(&key[1], client_public_key, 32);
      
}



void clientChangeCipherSpec(struct tls_record_header* tls) {

   //record header
   tls->record_type = 0x14;  //handshake message
   tls->ver[0] = 0x03;
   tls->ver[1] = 0x03;    // TLS 1.0
   tls->length[1] = 1;
   tls->payload[0] = 1;    //the payload of this message is defined as th ebyte 0x01
}


void evpPubkey_to_buffer(EVP_PKEY *pkey, unsigned char*  buf){
   int pkeyLen;
   unsigned char *ucTempBuf;
   pkeyLen = i2d_PublicKey(pkey, NULL);
   buf = (unsigned char *)malloc(pkeyLen+1);
   ucTempBuf = buf;
   i2d_PublicKey(pkey, &ucTempBuf);
   int ii;
   printf("CLIENT PUBLIC KEY:\n");
   for(ii = 0; ii < pkeyLen; ii++){
      printf("%02x\n", (unsigned char) buf[ii]);
   }
}

void handleErrors(const char* tag)
{
	int error;
	int depth;
	printf("OPENSSL ERROR [\"%s\"]\n", tag);

	for(depth = 0, error = ERR_get_error(); error > 0; error = ERR_get_error(), depth++) {
		printf("#%02d: LIB:\"%s\" FUNC:\"%s\" REASON:\"%s\"\n",
				depth,
				ERR_lib_error_string(error),
				ERR_func_error_string(error),
				ERR_reason_error_string(error));
	}

	printf("\n");
}

EVP_PKEY * get_peerkey(const unsigned char * buffer, size_t buffer_len)
{
    EC_KEY *tempEcKey = NULL;
    EVP_PKEY *peerkey = NULL;

    // change this if another curve is required
    tempEcKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if(tempEcKey == NULL) {
        handleErrors("Preparing new curve for server public key");
        EC_KEY_free(tempEcKey);
        return NULL;
    }

    if(EC_KEY_oct2key(tempEcKey, buffer, buffer_len, NULL) != 1)  {
        handleErrors("Converting raw server public key");
        EC_KEY_free(tempEcKey);
        return NULL;
    }

    if(EC_KEY_check_key(tempEcKey) != 1) {
        handleErrors("Sanity check on server public key");
        EC_KEY_free(tempEcKey);
        return NULL;
    }

    peerkey = EVP_PKEY_new();
    if(peerkey == NULL) {
        handleErrors("Preparing EVP_PKEY for server public key");
        EC_KEY_free(tempEcKey);
        return NULL;
    }

    if(EVP_PKEY_assign_EC_KEY(peerkey, tempEcKey)!= 1) {
        handleErrors("Assigning server public key");
        EC_KEY_free(tempEcKey);
        EVP_PKEY_free(peerkey);
        return NULL;
    }

    return peerkey;
}



/*
   ===================================================================
   ============================  M A I N  ============================
   ===================================================================
 */

char sent[1000];
char received[100000];

unsigned char client_pub_key[1000];
unsigned char client_priv_key[1000];
unsigned char server_pub_key[65];

char client_random[32];
char server_random[32];


struct sockaddr_in server;
unsigned char ip[4]={216,58,204,68};   //google


int main() {

   int s,j,n,length,l;

   EVP_PKEY_CTX *pctx, *kctx;
   EVP_PKEY_CTX *ctx;
   EVP_PKEY *pkey = NULL, *peerkey, *params = NULL;

   EC_KEY *a;
   EVP_PKEY *a_evppkey;

   unsigned char * secret;
   size_t secret_len = 32;
   unsigned char ms[] = "master secret";

   struct tls_record_header * tls;
   struct handshake_header * hh;
   struct client_hello * ch;
   struct server_hello * sh;
   struct key_exchange * ke;

   //intialise tcp socket
   s=socket(AF_INET, SOCK_STREAM, 0);
   if(s==-1){
      perror("socket fallita");
      return 1;
   }
   printf("Socket inizializzato\n");

   server.sin_family = AF_INET;
   server.sin_port = htons(443);
   server.sin_addr.s_addr = *(unsigned int *)ip;

   //connect to server
   if ( connect(s, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) == -1 ){
      perror("Connect fallita");
      return 1;
   }

   printf("\nConnect completata\n");

   //TLS 1.2 clienthello

   tls = (struct tls_record_header *) sent;
   hh = (struct handshake_header *) tls->payload;
   ch = (struct client_hello *) hh->message;

   clientHello(tls, hh, ch, client_random);

   length = 68;  // clienthello total length

   printf("\nCLIENT HELLO\n\n");
   stampa_buffer(sent, length);

   //send CLIENT HELLO  
   write(s, sent, length);
   
   //receive from server
   length = 10000;  // buffer length

   for(j=0; n=read(s,received+j,length-j); j += n){  
      if (n == -1) {
         perror("read failed");
         return 1;
      }
   }

   //read serverhello
   tls = (struct tls_record_header *) received;
   hh = (struct handshake_header *) tls->payload;
   sh = (struct server_hello *) hh->message;
   
   length = (tls->length[1])+5;
   printf("\nSERVER HELLO:\n\n");
   stampa_buffer(received, length);

   //save server random
   memcpy(server_random, sh->random, 32);
   printf("CLIENT RANDOM:\n");
   stampa_buffer(client_random, 32);

   printf("SERVER RANDOM:\n");
   stampa_buffer(server_random, 32);


   //move to read next message
   tls = (struct tls_record_header *) (received + length);
   hh = (struct handshake_header *) tls->payload;

   //------------------------------------------------------------------------------- Server Certificate
   if(hh->type == 0x0b) {
      length = htons(*((unsigned short *) tls->length))+5;
      printf("\n\nCERTIFICATE: \n\n");
      stampa_buffer((unsigned char*) tls, length);
   }

   //move again
   tls = (struct tls_record_header *) ((unsigned char*)tls + length);
   hh = (struct handshake_header *) tls->payload;

   //-------------------------------------------------------------------------------- Server Key Exchange
   if(hh->type == 0x0c) {
      printf("\n\nSERVER KEY EXCHANGE :\n\n");
      length = htons(*((unsigned short *) tls->length))+5;
      stampa_buffer((unsigned char*) tls, length);

      ke = (struct key_exchange *) hh->message;

      // save ephemeral public key that the server just sent (we will not be using the certificate's public key 
      // since we are using ec-diffie-hellman key exchange algorithm)
      
      if((ke->curve_type == 0x03) && (ke->curve_id[1] == 0x17)){
         // 03 = named curve  
         // 001d = curve x25519
         memcpy(server_pub_key, ke->key, ke->key_len);

         printf("\nSERVER EPHEMERAL PUBLIC KEY:\n");
         stampa_buffer(server_pub_key, ke->key_len); //ke->key_len = 65 -> 64 bytes of key + 1 byte prefix in uncompressed form

      }
   }

   //move again
   tls = (struct tls_record_header *) ((unsigned char*)tls + length);
   hh = (struct handshake_header *) tls->payload;

   //--------------------------------------------------------------------------------- Server Hello Done
   if(hh->type == 0x0e) {
      printf("\n\nSERVER HELLO DONE :\n\n");
      length = htons(*((unsigned short *) tls->length))+5;
      stampa_buffer((unsigned char*) tls, length);
   }


   //generate client keypair

   //create context for parameter generation
   if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))){
      printf("Error during Context creation\n");
   }

   //initialise parameter generation
   if(1 != EVP_PKEY_paramgen_init(pctx)){
      printf("Error during parameter generation\n");
   }

   //use X9.62 prime256v1 curve
   if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)){
      printf("Error setting the named curve parameter\n");
   }

   //create the parameter params
   if(!EVP_PKEY_paramgen(pctx, &params)){
      printf("Error creating parameters\n");
   }

   //create the context for the key generation
   if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))){
      printf("Error creating context for key ceneration\n");
   }

   //convert server key saved inside server_pub_key buffer to EVP_PKEY
   /*
   if(NULL == (a = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))){
      printf("ERROR 1\n");
   }
   EVP_PKEY * temp = a;
   peerkey = d2i_PublicKey(EVP_PKEY_EC, &temp, (const unsigned char **) &server_pub_key, 65);
   if(peerkey == NULL){
   //if(0 == i2d_PublicKey(peerkey,(unsigned char **) &server_pub_key)){   
      printf("ERROR 2\n");
   }
   */

   peerkey = get_peerkey(server_pub_key, sizeof(server_pub_key));
   
   //generate CLIENT's key pair
   if(1 != EVP_PKEY_keygen_init(kctx)){
      printf("Error init\n");
   }
   if(1 != EVP_PKEY_keygen(kctx, &pkey)){
      printf("Error generating keypair\n");
   }

   // create context for the shared secret derivation
   if(NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL))){
      printf("Error 3\n");
   }

   // initialise
   if(1 != EVP_PKEY_derive_init(ctx)){
      printf("Error 4\n");
   }
   //provide the server's public key
   if(1 != EVP_PKEY_derive_set_peer(ctx, peerkey)){
      printf("Error 5\n");
   }
   //determine the buffer length of the shared secret
   if(1 != EVP_PKEY_derive(ctx, NULL, &secret_len)){
      printf("Error 6\n");
   }

   printf("HEY\n");

   //create the buffer
   secret = OPENSSL_malloc(secret_len);

   //DERIVE THE SHARED SECRET (PRE-MASTER SECRET)
   if(1 != (EVP_PKEY_derive(ctx, secret, &secret_len))){
      printf("Shared secret derivation error\n");  
   }
   else printf("EPIC\n");


   EVP_PKEY_CTX_free(ctx);
   EVP_PKEY_free(peerkey);
   EVP_PKEY_free(pkey);
   EVP_PKEY_CTX_free(kctx);
   EVP_PKEY_free(params);
   EVP_PKEY_CTX_free(pctx);

/*

   //provide the server with our public key
   evpPubkey_to_buffer(pkey, client_pub_key);

   printf("CLIENT PUBLIC KEY\n");
   stampa_buffer(client_pub_key, 1000);
   
   //clean buffer
   bzero(sent, 1000);
   
   //generate ----------------------------------------------------- ClientKeyExchange Message
   tls = (struct tls_record_header *) sent;
   hh = (struct handshake_header *) tls->payload;
   
   clientKeyExchange(tls, hh, client_pub_key);

   length = 42;  //clientkeyexchange length

   printf("\nCLIENT KEY EXCHANGE\n\n");
   stampa_buffer(sent, length);
   
   //generate ----------------------------------------------------- ChangeCipherSpec Message
   tls = (struct tls_record_header *) sent+length;

   clientChangeCipherSpec(tls);
   
   l = 6;  //changecipherspec length
   length += l;

   printf("\nCLIENT CHANGE CIPHER SPEC\n\n");


   //generate ----------------------------------------------------- Client Finished Message
   tls = (struct tls_record_header *) sent+length;
   hh = (struct handshake_header *) tls->payload;

   clientFinished(tls);
   
   //l = ;  //client Finished length
   length += l;

   printf("\nCLIENT FINISHED\n\n");
   stampa_buffer(tls, l);

   
   //send CLIENT KEY EXCHANGE, Client CHANGE CIPHER SPEC and Client FINISHED  
   write(s, sent, length);


   // Receive from Server 
   // changeCipherSpec 
   // Finished


   //clean buffer
   bzero(received, 10000);
   
   length = 10000;

   //receive from server
   for(j=0; n=read(s,received+j,length-j); j += n){  
      if (n == -1) {
         perror("read fallita");
         return 1;
      }
   }

   //printf("\n");
   //stampa_buffer(received, j);  

   //read changecipherspec

   tls = (struct tls_record_header *) received;
   
   length = (tls->length[1])+5;
   printf("\nSERVER CHANGE CIPHER SPEC:\n\n");
   stampa_buffer(received, length);

   //move to read next message
   tls = (struct tls_record_header *) (received + length);
   
   //read server finished (encrypted) 
   length = (tls->length[1])+5;
   printf("\nSERVER FINISHED (ENCRYPTED):\n\n");
   stampa_buffer(received, length);
*/

   //handshake complete
   close(s);
}
