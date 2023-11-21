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
	void SetUp() override {
		default_seapp_context_ = StringPrintf("%s/seapp_contexts", tdir_.path);
		default_seapp_path_alts_ = { .paths = {
			{ default_seapp_context_.c_str() }
		}};
	}

	TemporaryDir tdir_;
	string default_seapp_context_;
	path_alts_t default_seapp_path_alts_;
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

	const path_alts_t service_paths = { .paths = {
		{ service_contexts.c_str(), unused_service_contexts.c_str() },
		{ vendor_contexts.c_str() }
	}};

	struct selabel_handle *handle = context_handle(
		SELABEL_CTX_ANDROID_SERVICE, &service_paths, "test_service");
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

	const path_alts_t service_paths = { .paths = {
		{ service_contexts.c_str() }
	}};

	struct selabel_handle *handle = context_handle(
		SELABEL_CTX_ANDROID_SERVICE, &service_paths, "test_service");
	EXPECT_EQ(handle, nullptr);
}

TEST_F(AndroidSELinuxTest, LoadAndLookupSeAppContext)
{

	WriteStringToFile(
		"# some comment\n"
		"user=_app seinfo=platform domain=platform_app type=app_data_file levelFrom=user\n",
	default_seapp_context_);

	EXPECT_EQ(seapp_context_reload_internal(&default_seapp_path_alts_), 0);

	context_t ctx = context_new("u:r:unknown");
	int ret = seapp_context_lookup_internal(SEAPP_DOMAIN, 10001, false, "platform", "com.android.test1", ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_STREQ(context_str(ctx), "u:r:platform_app:s0:c512,c768");
	context_free(ctx);

	ctx = context_new("u:r:unknown_data_file");
	ret = seapp_context_lookup_internal(SEAPP_TYPE, 10001, false, "platform", "com.android.test1", ctx);
	EXPECT_EQ(ret, 0);
	EXPECT_STREQ(context_str(ctx), "u:r:app_data_file:s0:c512,c768");
	context_free(ctx);
}

TEST_F(AndroidSELinuxTest, LoadSeAppContextInsecure)
{
	WriteStringToFile(
		"user=_app name=com.android.test domain=platform_app type=app_data_file\n",
	default_seapp_context_);

	EXPECT_EQ(seapp_context_reload_internal(&default_seapp_path_alts_), -1);

	WriteStringToFile(
		"user=_app name=com.android.test isSdkSandbox=true domain=platform_app type=app_data_file\n",
	default_seapp_context_);

	EXPECT_EQ(seapp_context_reload_internal(&default_seapp_path_alts_), -1);

	WriteStringToFile(
		"user=_app isPrivApp=false name=com.android.test domain=platform_app type=app_data_file\n",
	default_seapp_context_);

	EXPECT_EQ(seapp_context_reload_internal(&default_seapp_path_alts_), -1);
}

TEST_F(AndroidSELinuxTest, LoadSeAppContextInsecureWithSeInfoOrPrivApp)
{
	WriteStringToFile(
		"user=_app isPrivApp=true name=com.android.test domain=platform_app type=app_data_file\n",
	default_seapp_context_);

	EXPECT_EQ(seapp_context_reload_internal(&default_seapp_path_alts_), 0);

	WriteStringToFile(
		"user=_app seinfo=platform name=com.android.test domain=platform_app type=app_data_file\n",
	default_seapp_context_);

	EXPECT_EQ(seapp_context_reload_internal(&default_seapp_path_alts_), 0);
}

TEST(AndroidSeAppTest, ParseValidSeInfo)
{
	struct parsed_seinfo info;
	memset(&info, 0, sizeof(info));

	string seinfo = "default:privapp:targetSdkVersion=10000:partition=system:complete";
	int ret = parse_seinfo(seinfo.c_str(), &info);

	EXPECT_EQ(ret, 0);
	EXPECT_STREQ(info.base, "default");
	EXPECT_EQ(info.targetSdkVersion, 10000);
	EXPECT_STREQ(info.isSelector, "isPrivApp");
	EXPECT_STREQ(info.partition, "system");

	seinfo = "platform:ephemeralapp:partition=system:complete";
	ret = parse_seinfo(seinfo.c_str(), &info);

	EXPECT_EQ(ret, 0);
	EXPECT_STREQ(info.base, "platform");
	EXPECT_EQ(info.targetSdkVersion, 0);
	EXPECT_STREQ(info.isSelector, "isEphemeralApp");
	EXPECT_STREQ(info.partition, "system");

	seinfo = "bluetooth";
	ret = parse_seinfo(seinfo.c_str(), &info);

	EXPECT_EQ(ret, 0);
	EXPECT_STREQ(info.base, "bluetooth");
	EXPECT_EQ(info.targetSdkVersion, 0);
	EXPECT_STREQ(info.isSelector, "");

	seinfo = "default:isSdkSandboxNext:partition=system:complete";
	ret = parse_seinfo(seinfo.c_str(), &info);

	EXPECT_EQ(ret, 0);
	EXPECT_STREQ(info.base, "default");
	EXPECT_EQ(info.targetSdkVersion, 0);
	EXPECT_STREQ(info.isSelector, "isSdkSandboxNext");
	EXPECT_STREQ(info.partition, "system");
}

TEST(AndroidSeAppTest, ParseInvalidSeInfo)
{
	struct parsed_seinfo info;

	string seinfo = "default:targetSdkVersion:complete";
	int ret = parse_seinfo(seinfo.c_str(), &info);
	EXPECT_EQ(ret, -1);

	seinfo = "default:targetSdkVersion=:complete";
	ret = parse_seinfo(seinfo.c_str(), &info);
	EXPECT_EQ(ret, -1);

	seinfo = "default:privapp:ephemeralapp:complete";
	ret = parse_seinfo(seinfo.c_str(), &info);
	EXPECT_EQ(ret, -1);

	seinfo = "default:isANewSelector:isAnotherOne:complete";
	ret = parse_seinfo(seinfo.c_str(), &info);
	EXPECT_EQ(ret, -1);
}

TEST(AndroidSeAppTest, ParseOverflow)
{
	struct parsed_seinfo info;

	string seinfo = std::string(255, 'x');
	int ret = parse_seinfo(seinfo.c_str(), &info);
	EXPECT_EQ(ret, 0);
	EXPECT_STREQ(info.base, seinfo.c_str());

	seinfo = std::string(256, 'x');
	ret = parse_seinfo(seinfo.c_str(), &info);
	EXPECT_EQ(ret, -1);
}
