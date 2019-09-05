#ifndef LICENSE_H
#define LICENSE_H
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RawLicense RawLicense;

const char* license_last_error();
uint64_t license_current_timestamp();
void license_timestamp_to_string(uint64_t timestamp, char* buf, int len);
const char* compute_md5(uint8_t* data, int len);

/*未加密的License */
RawLicense* raw_license_construct(uint64_t from, uint64_t to, const char* customer, int* len);
bool raw_license_verify(RawLicense* license, uint64_t timestamp);
void raw_license_dump(RawLicense* license, char* buff, int len);
void raw_license_free(RawLicense* license);

/*加密和解密*/
uint8_t* private_key_encrypt_data(const char* private_key, const uint8_t* data, int len, int* encrypt);
uint8_t* public_key_decrypt_data(const uint8_t* data, int len, int* decrypt);

bool encrypted_license_gen(const char* save_path,
                           const char* private_key,
                           uint64_t from,
                           uint64_t to,
                           const char* customer);

RawLicense* encrypted_license_open(const char* path);

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif /*LICENSE_H*/
