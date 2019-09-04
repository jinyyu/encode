#include "license.h"
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/md5.h>

#define LOG_INFO(format, ...) { fprintf(stderr, "INFO " format "\n", ##__VA_ARGS__); }
#define LOG_FATAL(format, ...) do \
        { \
             fprintf(stderr, "FATAL " format "\n", ##__VA_ARGS__); \
             exit(EXIT_FAILURE); \
        } while(0)

#define MAGIC_STR ("AtlasDB")
#define MAX_CUSTOMER_LEN (32)

const char* PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n"
                         "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArOuglPZzFqSgCU7iI+Uh\n"
                         "hc4NL5Rq6saWni7/IZFW0kX5kpB07Cekyd88YE1Tfc1AW0F0nozj574Oybpkljd9\n"
                         "wF/WIgHI3qUwvdaRIDV0EKpFs4wiqxh/wPfNvv11JJxRY3B57hAmeZv5Isfdt+ft\n"
                         "sLDZTmzKkLquTSB+8eUjF0neYcyxb0kkFqy6lP42qxx504lCv7zPY/bjfL8ahO+2\n"
                         "kz3n1aG6zHvlY53/amoQ8+3wo1nz6Ve6F1x+AE41+jBfFxMqwezR009TTwqeuUDy\n"
                         "xv/UNm6fvc10/UX5E/01154836ZsZcains8kkixznJaaTUmlS/yu5/L/UVXZWXWE\n"
                         "+wIDAQAB\n"
                         "-----END PUBLIC KEY-----\n";

static bool openssl_error_load = false;


/* 取消内存对齐 */
#pragma pack(push, 1)
typedef struct RawLicenseData {
  uint64_t from;          /*授权开始时间*/
  uint64_t to;            /*权结束时间*/
  uint8_t customer[0];    /*客户字符串, 包含结尾\0*/
} RawLicenseData;

typedef struct RawLicense {
  uint64_t magic;         /*固定值*/
  uint8_t md5[32];        /*RawLicenseData 的 md5*/
  uint16_t data_len;      /*RawLicenseData 的长度 */
  RawLicenseData data[0]; /* 证书信息 */
} RawLicense;
#pragma pack(pop)

static uint64_t get_magic_number();
static const char* openssl_last_error();

static uint64_t get_magic_number() {
  uint64_t ret;
  memcpy(&ret, MAGIC_STR, sizeof(ret));
  return ret;
}
/*
 * 系统当前时间戳
 */
uint64_t license_current_timestamp() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec;
}

/*
 * 生成原始证书
 * from: 开始时间
 * to: 到期时间
 * customer: 客户名
 * 返回 malloc 内存
 */
RawLicense* raw_license_construct(uint64_t from, uint64_t to, const char* customer) {
  RawLicense* hdr;
  const char* md5_str;
  size_t customer_len = strlen(customer);
  size_t license_data_len = sizeof(RawLicenseData) + 1 + customer_len;
  size_t total_len = sizeof(RawLicense) + license_data_len;

  if (from >= to) {
    LOG_FATAL("invalid param, from %lu, to %lu", from, to);
  }
  if (!customer) {
    LOG_FATAL("invalid customer");
  }
  if (license_data_len > MAX_CUSTOMER_LEN) {
    LOG_FATAL("customer too long: %lu", customer_len);
  }
  hdr = (RawLicense*) malloc(total_len);
  memset(hdr, 0, total_len);
  hdr->data->from = from;
  hdr->data->to = to;
  memcpy(hdr->data->customer, customer, customer_len);
  hdr->data_len = license_data_len;
  hdr->magic = get_magic_number();

  md5_str = compute_md5((uint8_t*) hdr->data, hdr->data_len);
  memcpy(hdr->md5, md5_str, 32);

  hdr->data_len = license_data_len;
  return hdr;
}

bool raw_license_verify(RawLicense* license, uint64_t timestamp) {
  const char* md5_str;
  if (license->magic != get_magic_number()) {
    char buf[8];
    memcpy(buf, &license->magic, 8);
    LOG_INFO("invalid magic %02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-",
             buf[0],
             buf[1],
             buf[2],
             buf[3],
             buf[4],
             buf[5],
             buf[6],
             buf[7]);
    return false;
  }

  if (license->data_len > MAX_CUSTOMER_LEN) {
    LOG_INFO("license too long %d", license->data_len);
    return false;
  }

  md5_str = compute_md5((uint8_t*) license->data, license->data_len);
  if (memcmp(md5_str, license->md5, 32) != 0) {
    char buf[33] = {0,};
    memcpy(buf, license->md5, 32);
    LOG_INFO("invalid md5, %s %s", md5_str, buf);
    return false;
  }
  LOG_INFO("md5 = [%s]", md5_str);

  if (timestamp < license->data->from || timestamp > license->data->to) {
    LOG_INFO("license expired (from %lu to %lu, now %lu)", license->data->from, license->data->to, timestamp);
    return false;
  }
  LOG_INFO("for [%s]", (const char*) license->data->customer);
  return true;
}

/*
 * 释放内存
 */
void raw_license_free(RawLicense* license) {
  free((void*) license);
}

static const char* openssl_last_error() {
  if (!openssl_error_load) {
    SSL_load_error_strings();
    openssl_error_load = true;
  }
  return ERR_error_string(ERR_get_error(), NULL);
}

/*
 * 使用私钥加密数据
 * private_key: 私钥
 * data: 数据
 * len: 数据的长度
 * encrypted: 返回加密后的长度
 * 成功返回 malloc 内存，失败返回 NULL
 */
uint8_t* private_key_encrypt_data(const char* private_key, const uint8_t* data, int len, int* encrypted) {
  RSA* rsa = NULL;
  BIO* bufio = NULL;
  int rsa_size;
  uint8_t* ret = NULL;
  uint8_t* buff;

  bufio = BIO_new(BIO_s_mem());
  BIO_puts(bufio, private_key);

  rsa = PEM_read_bio_RSAPrivateKey(bufio, NULL, NULL, NULL);

  if (!rsa) {
    LOG_INFO("PEM_read_bio_RSAPrivateKey error %s", openssl_last_error());
    goto cleanup;
  }

  rsa_size = RSA_size(rsa);
  buff = malloc(rsa_size);

  *encrypted = RSA_private_encrypt(len, (const uint8_t*) data, buff, rsa, RSA_PKCS1_PADDING);
  if (*encrypted == -1) {
    LOG_INFO("RSA_private_encrypt error %s", openssl_last_error());
    free(buff);
    goto cleanup;
  }
  ret = buff;

cleanup:
  if (rsa) {
    RSA_free(rsa);
  }
  if (bufio) {
    BIO_free(bufio);
  }
  CRYPTO_cleanup_all_ex_data();
  return ret;
}

/*
 * 使用公钥解密数据
 * data: 数据
 * len: 数据的长度
 * decrypt: 返回解密后的长度
 * 成功返回 malloc 内存，失败返回 NULL
 */
uint8_t* public_key_decrypt_data(const uint8_t* data, int len, int* decrypt) {
  RSA* rsa = NULL;
  BIO* bufio = NULL;
  int rsa_size;
  uint8_t* ret = NULL;
  uint8_t* buff;

  bufio = BIO_new(BIO_s_mem());
  BIO_puts(bufio, PUBLIC_KEY);

  rsa = PEM_read_bio_RSA_PUBKEY(bufio, NULL, NULL, NULL);

  if (!rsa) {
    LOG_INFO("PEM_read_bio_RSA_PUBKEY error %s", openssl_last_error());
    goto cleanup;
  }

  rsa_size = RSA_size(rsa) - 11;
  buff = malloc(rsa_size);

  *decrypt = RSA_public_decrypt(len, (const uint8_t*) data, buff, rsa, RSA_PKCS1_PADDING);
  if (*decrypt == -1) {
    LOG_INFO("RSA_public_encrypt error %s", openssl_last_error());
    free(buff);
    goto cleanup;
  }
  ret = buff;

cleanup:
  if (rsa) {
    RSA_free(rsa);
  }
  if (bufio) {
    BIO_free(bufio);
  }
  CRYPTO_cleanup_all_ex_data();

  return ret;
}

/*
 * 计算 md5
 * 返回 32字节 md5 字符串，线程不安全
 */
const char* compute_md5(uint8_t* data, int len) {
  static char md5_string[33];
  MD5_CTX ctx;
  uint8_t md[16];

  memset(md5_string, 0, sizeof(md5_string));
  MD5_Init(&ctx);
  MD5_Update(&ctx, data, len);
  MD5_Final(md, &ctx);
  snprintf(md5_string,
           sizeof(md5_string),
           "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
           md[0],
           md[1],
           md[2],
           md[3],
           md[4],
           md[5],
           md[6],
           md[7],
           md[8],
           md[9],
           md[10],
           md[11],
           md[12],
           md[13],
           md[14],
           md[15]
  );
  return md5_string;
}