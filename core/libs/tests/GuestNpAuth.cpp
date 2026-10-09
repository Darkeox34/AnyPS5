#include "prx/libc/include/general/VabiMacros.hpp"
#include <cstdint>
#include <cstdlib>

extern "C" {
int APS5_VABI sceNpAuthAbortRequest(int req_id);
int APS5_VABI sceNpAuthCreateAsyncRequest(const void* param);
int APS5_VABI sceNpAuthCreateRequest(void);
int APS5_VABI sceNpAuthDeleteRequest(int req_id);
int APS5_VABI sceNpAuthGetAuthorizationCodeV3(int req_id, const void* param, void* auth_code, int* issuer_id);
int APS5_VABI sceNpAuthGetIdTokenV3(int req_id, const void* param, void* id_token);
int APS5_VABI sceNpAuthPollAsync(int req_id, int* result);
int APS5_VABI sceNpAuthWaitAsync(int req_id, int* result);
}

namespace {

void Require(bool value) { if (!value) std::abort(); }

constexpr int kErrInvalidArgument = static_cast<int>(0x80550003);
constexpr int kErrSignedOut = static_cast<int>(0x80550006);
constexpr int kPollAsyncFinished = 0;

}

int main() {
    int req1 = sceNpAuthCreateRequest();
    Require(req1 > 0);

    const int dummyParam = 42;
    int req2 = sceNpAuthCreateAsyncRequest(&dummyParam);
    Require(req2 > req1);

    Require(sceNpAuthAbortRequest(req1) == 0);
    Require(sceNpAuthDeleteRequest(req1) == 0);

    char buffer[128] = {};
    int issuerId = 0;

    Require(sceNpAuthGetAuthorizationCodeV3(req2, nullptr, buffer, &issuerId) == kErrInvalidArgument);
    Require(sceNpAuthGetAuthorizationCodeV3(req2, &dummyParam, nullptr, &issuerId) == kErrInvalidArgument);
    Require(sceNpAuthGetAuthorizationCodeV3(req2, &dummyParam, buffer, &issuerId) == kErrSignedOut);

    Require(sceNpAuthGetIdTokenV3(req2, nullptr, buffer) == kErrInvalidArgument);
    Require(sceNpAuthGetIdTokenV3(req2, &dummyParam, nullptr) == kErrInvalidArgument);
    Require(sceNpAuthGetIdTokenV3(req2, &dummyParam, buffer) == kErrSignedOut);

    int asyncResult = 0;
    Require(sceNpAuthPollAsync(req2, &asyncResult) == kPollAsyncFinished);
    Require(asyncResult == kErrSignedOut);

    asyncResult = 0;
    Require(sceNpAuthWaitAsync(req2, &asyncResult) == 0);
    Require(asyncResult == kErrSignedOut);

    Require(sceNpAuthPollAsync(req2, nullptr) == kPollAsyncFinished);
    Require(sceNpAuthWaitAsync(req2, nullptr) == 0);
}
