#include <gtest/gtest.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>

#include "android_internal.h"
#include "label_internal.h"

using android::base::StringPrintf;
using android::base::WriteStringToFile;
using std::string;

class AndroidSELinuxTest : public ::testing::Test {
    protected:
	TemporaryDir tdir_;
};

TEST_F(AndroidSELinuxTest, LoadAndLookupServiceContext)
{
	string service_contexts =
		StringPrintf("%s/service_contexts", tdir_.path);
	string unused_service_contexts =
		StringPrintf("%s/unused_contexts", tdir_.path);
	string vendor_contexts =
		StringPrintf("%s/vendor_service_contexts", tdir_.path);

	WriteStringToFile("account  u:object_r:account_service:s0\n",
			  service_contexts);
	WriteStringToFile("ignored  u:object_r:ignored_service:s0\n",
			  unused_service_contexts);
	WriteStringToFile(
		"android.hardware.power.IPower/default  u:object_r:hal_power_service:s0\n",
		vendor_contexts);

	static const char *const
		service_paths[MAX_CONTEXT_PATHS][MAX_ALT_CONTEXT_PATHS] = {
			{ service_contexts.c_str(),
			  unused_service_contexts.c_str() },
			{ vendor_contexts.c_str() }
		};

	struct selabel_handle *handle = context_handle(
		SELABEL_CTX_ANDROID_SERVICE, service_paths, "test_service");
	EXPECT_NE(handle, nullptr);

	char *tcontext;
	EXPECT_EQ(selabel_lookup_raw(handle, &tcontext, "foobar",
				     SELABEL_CTX_ANDROID_SERVICE),
		  -1);

	EXPECT_EQ(selabel_lookup_raw(handle, &tcontext, "account",
				     SELABEL_CTX_ANDROID_SERVICE),
		  0);
	EXPECT_STREQ(tcontext, "u:object_r:account_service:s0");
	free(tcontext);

	EXPECT_EQ(selabel_lookup_raw(handle, &tcontext, "ignored",
				     SELABEL_CTX_ANDROID_SERVICE),
		  -1);

	EXPECT_EQ(selabel_lookup_raw(handle, &tcontext,
				     "android.hardware.power.IPower/default",
				     SELABEL_CTX_ANDROID_SERVICE),
		  0);
	EXPECT_STREQ(tcontext, "u:object_r:hal_power_service:s0");
	free(tcontext);

	selabel_close(handle);
}

TEST_F(AndroidSELinuxTest, FailLoadingServiceContext)
{
	string service_contexts =
		StringPrintf("%s/service_contexts", tdir_.path);

	WriteStringToFile("garbage\n", service_contexts);

	static const char *const
		service_paths[MAX_CONTEXT_PATHS][MAX_ALT_CONTEXT_PATHS] = {
			{ service_contexts.c_str() }
		};

	struct selabel_handle *handle = context_handle(
		SELABEL_CTX_ANDROID_SERVICE, service_paths, "test_service");
	EXPECT_EQ(handle, nullptr);
}
