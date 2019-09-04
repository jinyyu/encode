#include <stdio.h>
#include "license.h"
#include <gtest/gtest.h>
#include "private_key.h"

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