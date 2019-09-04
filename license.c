#include "license.h"
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>

#define LOG_INFO(format, ...) { fprintf(stderr, "INFO " format "\n", ##__VA_ARGS__); }
#define LOG_FATAL(format, ...) do \
        { \
             fprintf(stderr, "FATAL " format "\n", ##__VA_ARGS__); \
             exit(EXIT_FAILURE); \
        } while(0)

#define MAGIC_STR ("AtlasDB")
#define MAX_CUSTOMER_LEN 1024

static uint64_t get_magic_number() {
  uint64_t ret;
  memcpy(&ret, MAGIC_STR, sizeof(ret));
  return ret;
}

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
  GChecksum* md5;
  const gchar* md5_str;

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
  memset(hdr, 0, total_len );
  hdr->data->from = from;
  hdr->data->to = to;
  memcpy(hdr->data->customer, customer, customer_len);
  hdr->data_len = license_data_len;
  hdr->magic = get_magic_number();

  md5 = g_checksum_new(G_CHECKSUM_MD5);
  g_checksum_update(md5, (const uint8_t*) hdr->data, hdr->data_len);
  md5_str = g_checksum_get_string(md5);
  memcpy(hdr->md5, md5_str, 32);
  LOG_INFO("license md5 [%s]", md5_str);
  g_checksum_free(md5);

  hdr->data_len = license_data_len;
  return hdr;
}

bool raw_license_verify(RawLicense* license, uint64_t timestamp) {
  GChecksum* md5;
  const gchar* md5_str;

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

  md5 = g_checksum_new(G_CHECKSUM_MD5);
  g_checksum_update(md5, (const uint8_t*) license->data, license->data_len);
  md5_str = g_checksum_get_string(md5);
  if (memcmp(md5_str, license->md5, 32) != 0) {
    char buf[33] = {0,};
    memcpy(buf, license->md5, 32);
    LOG_INFO("invalid md5, %s %s", md5_str, buf);
    g_checksum_free(md5);
    return false;
  }
  LOG_INFO("md5 = [%s]", md5_str);
  g_checksum_free(md5);

  if (timestamp < license->data->from || timestamp > license->data->to) {
    LOG_INFO("license expired (from %lu to %lu, now %lu)", license->data->from, license->data->to, timestamp);
    return false;
  }
  LOG_INFO("for [%s]", (const char*)license->data->customer);
  return true;
}

void raw_license_free(RawLicense* license) {
  free((void*) license);
}

void test() {
  RawLicense* li = raw_license_construct(1, 4, "mysustomer");
  bool ok = raw_license_verify(li, 3);
  LOG_INFO("------------------%d", ok);
}
