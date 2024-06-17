// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "MinHook.h"
#include "opts.h"

void* buf;

void* tbuf;
size_t tsize;

void* rbuf;
size_t rsize;

void* nullptrForHook = nullptr;

template<typename T = void*>
__forceinline void Hook(void *ptr, void* detour, T& og = nullptrForHook) {
    MH_CreateHook(ptr, detour, std::is_same_v<T, void*> ? nullptr : (LPVOID*)&og);
}

__declspec(noinline) bool InternalCheckBytes(void* base, int ind, const uint8_t* bytes, size_t sz, bool upwards = false) {
    auto offBase = (uint8_t*)(upwards ? __int64(base) - ind : __int64(base) + ind);
    for (int i = 0; i < sz; i++) {
        if (*(offBase + i) != bytes[i]) return false;
    }
    return true;
}

template <uint8_t... Data>
class CheckBytes {
public:
    constexpr static uint8_t bytes[sizeof...(Data)] = { Data... };
    void* Base;
    int Ind;
    bool Upwards;

    CheckBytes(void* base, int ind, bool upwards = false) {
        Base = base;
        Ind = ind;
        Upwards = upwards;
    }

    operator bool() {
        return InternalCheckBytes(Base, Ind, bytes, sizeof...(Data), Upwards);
    }
};

template <typename T = void>
std::remove_pointer_t<T>* FollowRelative(void* base, int offset) {
    auto addr = (uint8_t *) (__int64(base) + offset + 4) + *(int32_t*)(__int64(base) + offset);
	return (std::remove_pointer_t<T>*) addr;
}

void *(*SelectEdit)(void *) = nullptr;
void *(*SelectReset)(void *) = nullptr;
char (*CompleteEdit)(void *) = nullptr;
wchar_t* VersionString = nullptr;

bool skip = false;

bool StringCallback(struct pf_patch_t* patch, void* stream) {
    void* saddr = FollowRelative<void>(stream, 3);
    if (__int64(saddr) >= __int64(rbuf) && __int64(saddr) < (__int64(rbuf) + (int64_t)rsize)) {
        if (wcscmp((wchar_t *) saddr, L"EditModeInputComponent0") == 0 && !SelectEdit && !SelectReset) {
            int sc = 0;
            for (int i = 1; i < 2048; i++) {
                if (CheckBytes<0x48, 0x8D, 0x05>(stream, i)) {
                    switch (sc) {
                    case 1:
						SelectEdit = FollowRelative<decltype(SelectEdit)>((uint8_t*) stream + i, 3);
                        break;
                    case 2:
						SelectReset = FollowRelative<decltype(SelectReset)>((uint8_t*) stream + i, 3);
                        break;
                    }
                    sc++;
                }
            }
        }
		else if (strcmp((char*)saddr, "CompleteBuildingEditInteraction") == 0 && !CompleteEdit) {
            for (int i = 1; i < 2048; i++) {
                if (CheckBytes<0x48, 0x8D>(stream, i, true)) {
                    CompleteEdit = FollowRelative<decltype(CompleteEdit)>((uint8_t *) stream - i, 3);
                    break;
                }
            }
        }
		else if (wcsncmp((wchar_t*)saddr, L"++Fortnite+Release-", 19) == 0 && !VersionString) {
			VersionString = (wchar_t*)saddr;
		}
    }
    return SelectEdit && SelectReset && CompleteEdit && VersionString;
}

bool EOR = false;


void* (*SelectEditOG)(void*);
void* __fastcall SelectEditHook(void* a1)
{
    void* result = SelectEditOG(a1);

    if (EOR) CompleteEdit(a1);

    return result;
}

void* (*SelectResetOG)(void*);
void* __fastcall SelectResetHook(void* a1)
{
    void* result = SelectResetOG(a1);

    if (EOR) CompleteEdit(a1);

    return result;
}

void Main() {
    buf = *(void**)(__readgsqword(0x60) + 0x10);

    auto section = pe_get_section((char*)buf, ".text");
    auto rsection = pe_get_section((char*)buf, ".rdata");

    tbuf = (void*)(__int64(buf) + section->virtualAddress);
    tsize = section->virtualSize;

    rbuf = (void*)(__int64(buf) + rsection->virtualAddress);
    rsize = rsection->virtualSize;

    constexpr static std::array<uint8_t, 2> matches = {
        0x48,
        0x8d
    };
    constexpr static std::array<uint8_t, 2> masks = {
        0xfb,
        0xff
    };

    constexpr static auto patch = pf_construct_patch((void*)matches.data(), (void*)masks.data(), 2, StringCallback);

    constexpr static pf_patch_t patches[] = {
        patch
    };

    constexpr static struct pf_patchset_t patchset = pf_construct_patchset(patches, sizeof(patches) / sizeof(struct pf_patch_t), pf_find_maskmatch);

    while (!pf_patchset_emit(tbuf, tsize, patchset));

	auto VStart = wcschr(VersionString, '-') + 1;
	auto VEnd = wcschr(VStart, '-');
	auto sz = (VEnd - VStart) * 2;
    wchar_t *s = (wchar_t *) malloc(sz + 2);
	__movsb((PBYTE) s, (const PBYTE) VStart, sz);
	s[sz] = 0;

    wchar_t* e;
	auto FNVer = wcstod(s, &e);
    MH_Initialize();
	if (FNVer < 11.00) Hook(SelectEdit, SelectEditHook, SelectEditOG);
    if (FNVer < 24.30) Hook(SelectReset, SelectResetHook, SelectResetOG);
    MH_EnableHook(MH_ALL_HOOKS);
    if (ActivationMethod == CommandLine || ActivationMethod == Both) {
        auto cmd = GetCommandLineA();
        if (strstr(cmd, "-eor")) {
            EOR = true;
        }
    }
	if (ActivationMethod == F6 || ActivationMethod == Both) {
		while (true) {
			if (GetAsyncKeyState(VK_F6) & 1) {
				EOR ^= 1;
			}
		}
	}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Main, NULL, 0, NULL);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

