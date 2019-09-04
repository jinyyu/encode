#ifndef LICENSE_H
#define LICENSE_H
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RawLicense RawLicense;

uint64_t license_current_timestamp();
const char* compute_md5(uint8_t* data, int len);

/*未加密的License */
RawLicense* raw_license_construct(uint64_t from, uint64_t to, const char* customer);
bool raw_license_verify(RawLicense* license, uint64_t timestamp);
void raw_license_free(RawLicense* license);

uint8_t* private_key_encrypt_data(const char* private_key, const uint8_t* data, int len, int* encrypt);
uint8_t* public_key_decrypt_data(const uint8_t* data, int len, int* decrypt);

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif /*LICENSE_H*/
