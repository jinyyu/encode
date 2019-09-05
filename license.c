#include "license.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <endian.h>
#include <assert.h>

static char ERROR_BUFF[1024];
#define LOG_ERROR(format, ...) do \
        { \
             snprintf(ERROR_BUFF, sizeof(ERROR_BUFF), "ERROR " format "\n", ##__VA_ARGS__); \
        } while(0)

#define MAGIC_STR ("AtlasDB")

const char* PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n"
                         "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArOuglPZzFqSgCU7iI+Uh\n"
                         "hc4NL5Rq6saWni7/IZFW0kX5kpB07Cekyd88YE1Tfc1AW0F0nozj574Oybpkljd9\n"
                         "wF/WIgHI3qUwvdaRIDV0EKpFs4wiqxh/wPfNvv11JJxRY3B57hAmeZv5Isfdt+ft\n"
                         "sLDZTmzKkLquTSB+8eUjF0neYcyxb0kkFqy6lP42qxx504lCv7zPY/bjfL8ahO+2\n"
                         "kz3n1aG6zHvlY53/amoQ8+3wo1nz6Ve6F1x+AE41+jBfFxMqwezR009TTwqeuUDy\n"
                         "xv/UNm6fvc10/UX5E/01154836ZsZcains8kkixznJaaTUmlS/yu5/L/UVXZWXWE\n"
                         "+wIDAQAB\n"
                         "-----END PUBLIC KEY-----\n";

static bool openssl_error_loaded = false;

/* 取消内存对齐 */
#pragma pack(push, 1)

/*证书信息*/
typedef struct RawLicenseContent {
  uint64_t from;          /*授权开始时间, 大端*/
  uint64_t to;            /*权结束时间, 大端*/
  uint8_t customer[0];    /*客户字符串, 包含结尾\0*/
} RawLicenseContent;

typedef struct RawLicense {
  uint64_t magic;             /*固定值*/
  uint8_t md5[32];           /*content 的 md5*/
  uint32_t content_len;      /*content 的长度, 大端 */
  RawLicenseContent content[0]; /* 证书信息 */
} RawLicense;
#pragma pack(pop)

/* 为了使加密不分片，限制客户名的长度 */
#define MAX_CUSTOMER_LEN (48)
#define MAX_LICENSE_CONTENT_LEN (MAX_CUSTOMER_LEN + sizeof(RawLicenseContent))

static uint64_t get_magic_number();
static const char* openssl_last_error();
static bool raw_license_verify_content(RawLicense* license);
static void clear_error_msg();

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
  clear_error_msg();
  gettimeofday(&tv, NULL);
  return tv.tv_sec;
}

/*
 * 时间戳转为字符串, 要求 len 至少 64 字节
 */
void license_timestamp_to_string(uint64_t timestamp, char* buf, int len) {
  struct timeval tm;
  struct tm result;
  tm.tv_sec = timestamp;
  tm.tv_usec = 0;

  assert(buf);
  assert(len >= 64);

  localtime_r(&tm.tv_sec, &result);
  snprintf(buf,
           len,
           "%04d-%02d-%02d %02d:%02d:%02d",
           result.tm_year + 1900,
           result.tm_mon + 1,
           result.tm_mday,
           result.tm_hour,
           result.tm_min,
           result.tm_sec);
}

/*
 * 生成原始证书
 * from: 开始时间
 * to: 到期时间
 * customer: 客户名
 * len: 返回 malloc 的长度
 * 返回 malloc 内存
 */
RawLicense* raw_license_construct(uint64_t from, uint64_t to, const char* customer, int* len) {
  RawLicense* hdr;
  const char* md5_str;
  size_t customer_len = strlen(customer) + 1;
  size_t content_len = sizeof(RawLicenseContent) + customer_len;
  size_t total_len = sizeof(RawLicense) + content_len;

  clear_error_msg();
  if (from >= to) {
    LOG_ERROR("invalid param, from %lu, to %lu", from, to);
    return NULL;
  }
  if (!customer) {
    LOG_ERROR("invalid customer");
    return NULL;
  }
  if (customer_len > MAX_CUSTOMER_LEN) {
    LOG_ERROR("customer too long: %lu", customer_len);
    return NULL;
  }

  if (len) {
    *len = total_len;
  }
  hdr = (RawLicense*) malloc(total_len);
  memset(hdr, 0, total_len);
  hdr->magic = get_magic_number();
  /*数值都转为大端*/
  hdr->content_len = htobe32(content_len);
  hdr->content->from = htobe64(from);
  hdr->content->to = htobe64(to);
  memcpy(hdr->content->customer, customer, customer_len);

  /*计算md5*/
  md5_str = compute_md5((uint8_t*) hdr->content, content_len);
  memcpy(hdr->md5, md5_str, 32);
  return hdr;
}

/*
 * 检验 RawLicense->magic 和 RawLicense->content 的 md5j是否合法
 */
static bool raw_license_verify_content(RawLicense* license) {
  const char* md5_str;
  uint32_t content_len;

  if (license->magic != get_magic_number()) {
    char buf[8];
    memcpy(buf, &license->magic, 8);
    LOG_ERROR("invalid magic %02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X-",
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

  /*数据类型从大端转到本机的节节序*/
  content_len = be32toh(license->content_len);

  if (content_len > MAX_LICENSE_CONTENT_LEN) {
    LOG_ERROR("license too long %d", content_len);
    return false;
  }

  /*校验证书的md5*/
  md5_str = compute_md5((uint8_t*) license->content, content_len);
  if (memcmp(md5_str, license->md5, 32) != 0) {
    char buf[33] = {0,};
    memcpy(buf, license->md5, 32);
    LOG_ERROR("invalid md5, %s %s", md5_str, buf);
    return false;
  }
  return true;
}

/*
 * 检验证书
 * timestamp: 当前时间戳
 */
bool raw_license_verify(RawLicense* license, uint64_t timestamp) {
  uint64_t from;
  uint64_t to;

  clear_error_msg();
  /*先校验数据块是否合法*/
  if (!raw_license_verify_content(license)) {
    return false;
  }

  /*数据类型从大端转到本机的节节序*/
  from = be64toh(license->content->from);
  to = be64toh(license->content->to);

  /*再校验证书的时间*/
  if (timestamp < from || timestamp > to) {
    LOG_ERROR("license expired [%lu, %lu], now: %lu", from, to, timestamp);
    return false;
  }
  return true;
}

/*
 * 返回证书信息，字符串, len 最少 256
 */
void raw_license_dump(RawLicense* license, char* buff, int len) {
  char from_str[64];
  char to_str[64];
  uint64_t from = be64toh(license->content->from);
  uint64_t to = be64toh(license->content->to);
  const char* customer = (const char*) license->content->customer;
  assert(len >= 256);
  license_timestamp_to_string(from, from_str, sizeof(from_str));
  license_timestamp_to_string(to, to_str, sizeof(to_str));

  snprintf(buff, len, "Customer     %s\n"
                      "Begins On    %s\n"
                      "Expires On   %s\n",
           customer,
           from_str,
           to_str);
}

/*
 * 释放内存
 */
void raw_license_free(RawLicense* license) {
  clear_error_msg();
  free((void*) license);
}

static const char* openssl_last_error() {
  if (!openssl_error_loaded) {
    SSL_load_error_strings();
    openssl_error_loaded = true;
  }
  return ERR_error_string(ERR_get_error(), NULL);
}

/*
 * 清除错误信息
 */
void clear_error_msg() {
  ERROR_BUFF[0] = 0;
}

/*
 * 返回错误信息，线程不安全
 */
const char* license_last_error() {
  if (ERROR_BUFF[0] == 0) {
    return "success";
  } else {
    return ERROR_BUFF;
  }
}

/*
 * 使用私钥加密数据
 * private_key: 私钥
 * content: 数据
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

  clear_error_msg();
  bufio = BIO_new(BIO_s_mem());
  BIO_puts(bufio, private_key);
  clear_error_msg();

  rsa = PEM_read_bio_RSAPrivateKey(bufio, NULL, NULL, NULL);

  if (!rsa) {
    LOG_ERROR("PEM_read_bio_RSAPrivateKey error %s", openssl_last_error());
    goto cleanup;
  }

  rsa_size = RSA_size(rsa);
  buff = malloc(rsa_size);

  /*已经限制了加密数据的长度，所以不会产生分片*/
  *encrypted = RSA_private_encrypt(len, (const uint8_t*) data, buff, rsa, RSA_PKCS1_PADDING);
  if (*encrypted == -1) {
    LOG_ERROR("RSA_private_encrypt error %s", openssl_last_error());
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
 * content: 数据
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

  clear_error_msg();

  rsa = PEM_read_bio_RSA_PUBKEY(bufio, NULL, NULL, NULL);

  if (!rsa) {
    LOG_ERROR("PEM_read_bio_RSA_PUBKEY error %s", openssl_last_error());
    goto cleanup;
  }

  rsa_size = RSA_size(rsa) - 11;
  buff = malloc(rsa_size);

  /*已经限制了加密数据的长度，所以不会产生分片*/
  *decrypt = RSA_public_decrypt(len, (const uint8_t*) data, buff, rsa, RSA_PKCS1_PADDING);
  if (*decrypt == -1) {
    LOG_ERROR("RSA_public_encrypt error %s", openssl_last_error());
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

/*
 * 生成加密的 license 文件，保存到指定地方
 * save_path: 保存路径
 * private_key: 私钥
 * from: 授权开始时间
 * to: 授权结束时间
 * customer: 客户名
 * 成功返回 true, 失败可以从 license_last_error() 拿到错误信息
 */
bool encrypted_license_gen(const char* save_path,
                           const char* private_key,
                           uint64_t from,
                           uint64_t to,
                           const char* customer) {
  RawLicense* lic = NULL;
  FILE* fp = NULL;
  bool ok = false;
  int license_len;
  uint8_t* encrypt_data = NULL;
  int encrypt_len;
  int write_len;

  clear_error_msg();
  fp = fopen(save_path, "wb");
  if (!fp) {
    LOG_ERROR("fopen error %s", strerror(errno));
    goto cleanup;
  }
  /*生成license*/
  lic = raw_license_construct(from, to, customer, &license_len);
  if (!lic) {
    goto cleanup;
  }

  /*用私钥加密license*/
  encrypt_data = private_key_encrypt_data(private_key, (const uint8_t*) lic, license_len, &encrypt_len);
  if (!encrypt_data) {
    goto cleanup;
  }
  if (encrypt_len <= 0) {
    LOG_ERROR("invalid encrypt data, %d", encrypt_len);
    goto cleanup;
  }

  write_len = htobe32(encrypt_len);

  /*写入证书的长度*/
  if (fwrite(&write_len, 1, 4, fp) != 4) {
    LOG_ERROR("fwrite error %s", strerror(errno));
    goto cleanup;
  }
  /*入证书的数据*/
  if (fwrite(encrypt_data, 1, encrypt_len, fp) != encrypt_len) {
    LOG_ERROR("fwrite error %s", strerror(errno));
    goto cleanup;
  }

  ok = true;

cleanup:
  if (lic) {
    raw_license_free(lic);
  }
  if (encrypt_data) {
    free(encrypt_data);
  }
  if (fp) {
    fclose(fp);
  }
  return ok;
}

/*
 * 打开 license
 * 失败时返回 NULL, 失败可以从 license_last_error() 拿到错误信息
 */
RawLicense* encrypted_license_open(const char* path) {
  uint8_t* encrypt_data = NULL;
  int encrypt_len;
  FILE* fp = NULL;
  RawLicense* lic = NULL;
  RawLicense* ret = NULL;
  int license_len;

  clear_error_msg();
  fp = fopen(path, "r");
  if (!fp) {
    LOG_ERROR("fopen error %s", strerror(errno));
    goto cleanup;
  }

  /*读长度*/
  if (fread(&encrypt_len, 1, 4, fp) != 4) {
    LOG_ERROR("invalid license");
    goto cleanup;
  }
  encrypt_len = be32toh(encrypt_len);

  /*大于 1M 肯定不是合法的 license */
  if (encrypt_len <= 0 || encrypt_len > 1024 * 1024) {
    LOG_ERROR("invalid license len %d", encrypt_len);
    goto cleanup;
  }
  encrypt_data = malloc(encrypt_len);

  /*读 license*/
  if (fread(encrypt_data, 1, encrypt_len, fp) != encrypt_len) {
    /*不是完整的 license*/
    LOG_ERROR("invalid license data");
    goto cleanup;
  }

  /*使用公钥匙解密*/
  lic = (RawLicense*) public_key_decrypt_data(encrypt_data, encrypt_len, &license_len);
  if (!lic) {
    /*解密失败*/
    goto cleanup;
  }
  /* 解密之后长度不够，肯定不是合法的 license */
  if (license_len < sizeof(RawLicense)) {
    LOG_ERROR("invalid license data");
    goto cleanup;
  }

  if (!raw_license_verify_content(lic)) {
    /*不是合法的证书*/
    goto cleanup;
  }

  ret = lic;

cleanup:
  if (fp) {
    fclose(fp);
  }
  if (encrypt_data) {
    free(encrypt_data);
  }
  return ret;
}