#include <sodium.h>
#include <stdio.h>
#include <string.h>

#define CHUNK_SIZE 4096 


static int phashing(const char* const password,unsigned char* const key,const unsigned char* salt){

    return crypto_pwhash(key, crypto_secretstream_xchacha20poly1305_KEYBYTES, password, strlen(password),salt,crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,crypto_pwhash_ALG_DEFAULT);
}
int fileCheek(const char* const target_file){
    FILE *file ;
    file= fopen(target_file,"rb");
    if(file){
        fclose(file);
        return 1;
    }
    return 0 ;
}
static int encryptFile(const char* const target_file, const char* const source_file,
        const char* const password){
    
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    // generate hashed-key based on random salt .
    randombytes_buf(salt ,sizeof salt);
    
    if(phashing(password,key,salt) != 0){
        printf("Error to generat secure password\n");
        return 1;
    };

    unsigned char  buf_in[CHUNK_SIZE];
    unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;

    
    FILE          *fp_t, *fp_s;
    
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    unsigned char  tag;

    // cheek if file existe
    fp_s = fopen(source_file, "rb");
    if (!fp_s) {
        printf("Error:\n\t-The source file is not existe\n");
        return 1;
    }
    // Initailse files
    if(fileCheek(target_file)){
        printf("Error:\n\t-OutPut File is Aready Existe\n");
        return 1;
    }
    fp_t = fopen(target_file, "wb");
    if (!fp_t) {
        printf("Error:\n\t-To open output file.\n");
        return 1;
    }
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    // write header and salt
    fwrite(salt, 1, sizeof salt, fp_t);
    fwrite(header, 1, sizeof header, fp_t);
    
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
                                                   NULL, 0, tag);
        fwrite(buf_out, 1, (size_t) out_len, fp_t);
    } while (! eof);
    fclose(fp_t);
    fclose(fp_s);
    return 0;
}

static int decryptFile(const char *target_file, const char *source_file,
        const char* const password){

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    
    
    unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_out[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    crypto_secretstream_xchacha20poly1305_state st;

    FILE           *fp_t, *fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    int            ret = -1;
    unsigned char  tag;

    // cheek if file existe
    fp_s = fopen(source_file, "rb");
    if (!fp_s) {
        printf("Error:\n\t-The source file is not existe\n");
        return 1;
    }
    // Initailse files
    if(fileCheek(target_file)){
        printf("Error:\n\t-OutPut File is Aready Existe\n");
        return 1;
    }
    fp_t = fopen(target_file, "wb");
    if (!fp_t) {
        printf("Error:\n\t-To open output file.\n");
        return 1;
    }

    // generate hashed-key bwith saved salt .
    fread(salt, 1, sizeof salt, fp_s);
    if(phashing(password,key,salt) != 0){
        printf("Error to generat secure password\n");
        return 1;
    };

     // read header from encryption file . 
    fread(header, 1, sizeof header, fp_s);
    
    // Verivication header Sign .
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        goto ret; /* incomplete header */
    }
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
                                                       buf_in, rlen, NULL, 0) != 0) {
            goto ret; /* corrupted chunk */
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            if (! eof) {
                goto ret; /* end of stream reached before the end of the file */
            }
        } else { /* not the final chunk yet */
            if (eof) {
                goto ret; /* end of file reached before the end of the stream */
            }
        }
        fwrite(buf_out, 1, (size_t) out_len, fp_t);
    } while (! eof);

    ret = 0;
    ret:
    fclose(fp_t);
    fclose(fp_s);
    return ret;
}
int cheek_arg(int argc,char* sc){

    if (argc != 5){

        printf("Usage :\n\t>> \"%s \" <encrypt|decrypt> <source File Path> <output File Path>  <password>\n",sc);
        return 1 ;
    }
    return 0;
}

int main(int argc , char* argv[])
{
    // verification argements.
    if(cheek_arg(argc,argv[0])) return 1;

    const char* type = argv[1];
    const char* source_FilePath = argv[2];
    const char* output_FilePath = argv[3];
    const char* password = argv[4];
   
    // Initializing Libsodium.
    if (sodium_init() != 0) {
        printf("Failed to initializing Libsodium.\n");
        return 1;
    }
    // printig varibales
    printf("source file :\t%s\noutput file :\t%s\nStart Process\n",source_FilePath,output_FilePath);
    switch ((*type)){
        case 'e':
            printf("Encryption....\n\n");
            if (encryptFile(output_FilePath,source_FilePath, password) != 0) {
                printf("Error to Encrypted \n");        
                return 1;
            }
            break;
        case 'd':
            printf("Decryption....\n\n");
            if (decryptFile(output_FilePath,source_FilePath, password) != 0) {
                printf("Error to Decrypted \n");        
                return 1;
            }
            break;
        default :
                printf("Please Follow The Usage guide\n");
            break;
    }

    printf("Job Done !\n");
    printf("LICENCED by : Coder_Yk !\n");
    return 0;
}
