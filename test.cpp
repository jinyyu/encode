#include <stdio.h>
#include "license.h"
#include <gtest/gtest.h>
#include "private_key.h"
#include <vector>

TEST(test, license) {
  struct Test {
    uint64_t from;
    uint64_t to;
    uint64_t tm;
    bool ok;
  };

  const char* str = "test customer";
  std::vector<Test> tests;
  tests.push_back(Test{.from = 1, .to = 10, .tm = 5, .ok = true});
  tests.push_back(Test{.from = 1, .to = 10, .tm = 1, .ok = true});
  tests.push_back(Test{.from = 1, .to = 10, .tm = 10, .ok = true});
  tests.push_back(Test{.from = 1, .to = 10, .tm = 0, .ok = false});
  tests.push_back(Test{.from = 1, .to = 10, .tm = 11, .ok = false});

  for (auto& t :  tests) {
    RawLicense* license = raw_license_construct(t.from, t.to, str);
    bool ok = raw_license_verify(license, t.tm);
    ASSERT_EQ(ok, t.ok);
    raw_license_free(license);
  }
}

TEST(test, encrypt) {
  struct Test {
    const char* raw;
  };
  std::vector<Test> tests;
  tests.push_back(Test{.raw = "some content",});
  tests.push_back(Test{.raw = "1234567890111213141516171819202122232425262729292922929292929292922",});

  for (auto& t : tests) {
    const char* raw = t.raw;

    int encrypt_len;
    uint8_t* encrypt_data = private_key_encrypt_data(PRIVATE_KEY, (const uint8_t*) raw, strlen(raw) + 1, &encrypt_len);
    ASSERT_TRUE(encrypt_data != NULL);

    int raw_len;
    uint8_t* raw_out = public_key_decrypt_data(encrypt_data, encrypt_len, &raw_len);
    ASSERT_EQ(raw_len, strlen(raw) + 1);
    ASSERT_EQ(strcmp(raw, (const char*) raw_out), 0);

    free(encrypt_data);
    free(raw_out);
  }
}

TEST(test, md5) {
  const char* src = "123456";
  const char* out = compute_md5((uint8_t*) src, strlen(src));
  ASSERT_EQ(strcmp(out, "e10adc3949ba59abbe56e057f20f883e"), 0);

  src = "abc";
  out = compute_md5((uint8_t*) src, strlen(src));
  ASSERT_EQ(strcmp(out, "900150983cd24fb0d6963f7d28e17f72"), 0);
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}