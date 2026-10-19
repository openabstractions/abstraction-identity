#define OA_IDENTITY_PATH_TESTING
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
static DWORD stale_structural_error=0;
static BOOL WINAPI observed_file_information(HANDLE file,LPBY_HANDLE_FILE_INFORMATION info) {
    BOOL result=::GetFileInformationByHandle(file,info);
    /* Successful Win32 calls may leave an unrelated ambient error in place. */
    if(result&&stale_structural_error)::SetLastError(stale_structural_error);
    return result;
}
#define GetFileInformationByHandle observed_file_information
#include "../path_identity_windows.h"
#undef GetFileInformationByHandle

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
UINT drive_type(const std::wstring& root) {
    return root == L"Y:\\" ? DRIVE_REMOTE : DRIVE_FIXED;
}

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void refused_before_open(const std::wstring& path, const std::wstring& folder, const char* label) {
    oa_identity_path::open_count = 0;
    bool refused = false;
    try {
        (void)oa_identity_path::within(path, folder);
    } catch (const oa_identity_path::Failure& error) {
        refused = error.kind == oa_identity_path::FailureKind::not_local;
    }
    require(refused, label);
    require(oa_identity_path::open_count == 0, "a refused local-path spelling reached CreateFileW");
}

struct TemporaryTree {
    std::wstring root;
    std::wstring project;
    std::wstring outside;

    TemporaryTree() {
        std::wstring temp(MAX_PATH, L'\0');
        const DWORD length = ::GetTempPathW(static_cast<DWORD>(temp.size()), temp.data());
        require(length != 0 && length < temp.size(), "GetTempPathW failed");
        temp.resize(length);
        wchar_t name[MAX_PATH]{};
        require(::GetTempFileNameW(temp.c_str(), L"oai", 0, name) != 0, "GetTempFileNameW failed");
        root = name;
        require(::DeleteFileW(root.c_str()) != FALSE, "DeleteFileW failed");
        require(::CreateDirectoryW(root.c_str(), nullptr) != FALSE, "CreateDirectoryW root failed");
        project = root + L"\\project";
        outside = root + L"\\outside";
        require(::CreateDirectoryW(project.c_str(), nullptr) != FALSE, "CreateDirectoryW project failed");
        require(::CreateDirectoryW(outside.c_str(), nullptr) != FALSE, "CreateDirectoryW outside failed");
    }

    ~TemporaryTree() {
        if (!project.empty()) ::RemoveDirectoryW(project.c_str());
        if (!outside.empty()) ::RemoveDirectoryW(outside.c_str());
        if (!root.empty()) ::RemoveDirectoryW(root.c_str());
    }
};

struct LiteralDotSpaceTwin {
    std::wstring normal_directory;
    std::wstring extended_directory;
    std::wstring normal_file;
    std::wstring extended_file;

    explicit LiteralDotSpaceTwin(const std::wstring& parent) {
        normal_directory = parent + L"\\literal";
        extended_directory = L"\\\\?\\" + parent + L"\\literal. ";
        normal_file = normal_directory + L"\\image";
        extended_file = extended_directory + L"\\image. ";
    }

    void create() {
        require(::CreateDirectoryW(normal_directory.c_str(), nullptr) != FALSE,
            "CreateDirectoryW normal twin failed");
        require(::CreateDirectoryW(extended_directory.c_str(), nullptr) != FALSE,
            "CreateDirectoryW extended literal directory failed");
        create_file(normal_file);
        create_file(extended_file);
    }

    ~LiteralDotSpaceTwin() {
        if (!extended_file.empty()) ::DeleteFileW(extended_file.c_str());
        if (!normal_file.empty()) ::DeleteFileW(normal_file.c_str());
        if (!extended_directory.empty()) ::RemoveDirectoryW(extended_directory.c_str());
        if (!normal_directory.empty()) ::RemoveDirectoryW(normal_directory.c_str());
    }

private:
    static void create_file(const std::wstring& path) {
        HANDLE file = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        require(file != INVALID_HANDLE_VALUE, "CreateFileW literal twin failed");
        require(::CloseHandle(file) != FALSE, "CloseHandle literal twin failed");
    }
};

void containment_uses_local_file_identity() {
    TemporaryTree tree;
    require(oa_identity_path::within(tree.project + L"\\new\\image.png", tree.project),
        "a missing descendant under the project was not contained");
    require(!oa_identity_path::within(tree.outside + L"\\image.png", tree.project),
        "a distinct local folder was counted as inside the project");
    require(!oa_identity_path::within(tree.project, tree.project),
        "the folder itself was counted as strictly inside itself");
}

void extended_paths_preserve_literal_dot_space_identity() {
    TemporaryTree tree;
    LiteralDotSpaceTwin twin(tree.project);
    twin.create();

    const auto extended_directory = oa_identity_path::identity_of(twin.extended_directory);
    const auto normal_directory = oa_identity_path::identity_of(twin.normal_directory);
    const auto extended_file = oa_identity_path::identity_of(twin.extended_file);
    const auto normal_file = oa_identity_path::identity_of(twin.normal_file);

    require(!(extended_directory.key == normal_directory.key),
        "the extended literal directory was reopened as its normalized twin");
    require(!(extended_file.key == normal_file.key),
        "the extended literal file was reopened as its normalized twin");
    require(oa_identity_path::base_name(extended_directory.final) == L"literal. ",
        "the extended literal directory's final path lost its trailing dot/space");
    require(oa_identity_path::within(twin.extended_file, twin.extended_directory),
        "the extended literal file was not contained by its exact directory");
    require(!oa_identity_path::within(twin.extended_file, twin.normal_directory),
        "the extended literal file was contained by its normalized directory twin");
    require(!oa_identity_path::within(twin.normal_file, twin.extended_directory),
        "the normalized twin file was contained by the extended literal directory");
}
void native_installer_identity_subset() {
    TemporaryTree tree;
    HANDLE folder=::CreateFileW(tree.project.c_str(),FILE_WRITE_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,nullptr);
    require(folder!=INVALID_HANDLE_VALUE,"case fixture open failed");
    DWORD flags=1;
    require(::SetFileInformationByHandle(folder,static_cast<FILE_INFO_BY_HANDLE_CLASS>(23),&flags,sizeof(flags))!=FALSE,"case-sensitive fixture unavailable");
    ::CloseHandle(folder);
    const wchar_t *names[]={L"K",L"k",L"\u212a",L"S",L"\u017f",L"\u00c5",L"\u212b",L"\u03a9",L"\u2126",L"\u039c",L"\u00b5",L"\u03c3",L"\u03c2"};
    std::vector<std::wstring> paths;
    for(const auto *name:names) {
        auto path=tree.project+L"\\"+name;
        HANDLE file=::CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
        require(file!=INVALID_HANDLE_VALUE,"distinct Unicode/case fixture create failed");::CloseHandle(file);paths.push_back(path);
    }
    {OA_NATIVE_FILE diagnostic{};BOOL opened=oa_native_open(paths[0].c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,FALSE,FALSE,&diagnostic);OA_NATIVE_FILE_ID key{};BOOL identified=opened&&oa_native_id(diagnostic.file,&key);std::cerr<<"native open="<<opened<<" id="<<identified<<" error="<<::GetLastError()<<"\n";oa_native_close(&diagnostic);}
    for(size_t i=0;i<paths.size();i++)for(size_t j=0;j<paths.size();j++) {
        const bool same=oa_native_same_paths(paths[i].c_str(),paths[j].c_str(),FALSE,FALSE)!=FALSE;
        if(same!=(i==j))std::cerr<<"native pair i="<<i<<" j="<<j<<" same="<<same<<" error="<<::GetLastError()<<"\n";
        require(same==(i==j),"native file IDs merged distinct twins");
    }
    OA_NATIVE_FILE held{};
    require(oa_native_open(paths[0].c_str(),GENERIC_READ,FILE_SHARE_READ,FALSE,FALSE,&held)!=FALSE,"held source open failed");
    require(::DeleteFileW(paths[0].c_str())==FALSE,"captured file was replaceable");
    require(::MoveFileW(tree.project.c_str(),(tree.project+L"-moved").c_str())==FALSE,"held ancestor was replaceable");
    oa_native_close(&held);
    require(oa_native_same_paths((tree.project+L"\\missing\\new").c_str(),(tree.project+L"\\missing\\new").c_str(),TRUE,TRUE)!=FALSE,"pending destination lost");
    require(oa_native_same_paths((tree.project+L"\\missing\\new").c_str(),(tree.outside+L"\\missing\\new").c_str(),TRUE,TRUE)==FALSE,"pending roots merged");
    require(oa_native_same_paths((tree.outside+L"\\missing\\new").c_str(),(tree.outside+L"\\MISSING\\NEW").c_str(),TRUE,TRUE)!=FALSE,"insensitive pending alias refused");
    require(oa_native_same_paths((tree.project+L"\\missing").c_str(),(tree.project+L"\\MISSING").c_str(),TRUE,TRUE)==FALSE,"sensitive pending twins merged");
    require(oa_native_open((tree.project+L"\\missing\\..\\new").c_str(),0,FILE_SHARE_READ,TRUE,TRUE,&held)==FALSE,"unsafe pending tail admitted");
    auto ordinary=tree.outside+L"\\Program.exe";
    HANDLE file=::CreateFileW(ordinary.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);require(file!=INVALID_HANDLE_VALUE,"alias fixture create failed");::CloseHandle(file);
    require(oa_native_same_paths(ordinary.c_str(),(tree.outside+L"\\PROGRAM.EXE").c_str(),FALSE,FALSE)!=FALSE,"case alias lost identity");
    wchar_t shortName[32768];DWORD count=::GetShortPathNameW(ordinary.c_str(),shortName,32768);
    if(count&&count<32768&&ordinary!=shortName)require(oa_native_same_paths(ordinary.c_str(),shortName,FALSE,FALSE)!=FALSE,"8.3 alias lost identity");
    else std::cout<<"8.3 alias unavailable on fixture volume.\n";
    auto link=tree.outside+L"\\link";
    require(::CreateDirectoryW(link.c_str(),nullptr)!=FALSE,"junction fixture directory create failed");
    HANDLE junction=::CreateFileW(link.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    require(junction!=INVALID_HANDLE_VALUE,"junction fixture open failed");
    const auto substitute=std::wstring(L"\\??\\")+tree.project;
    const auto print=tree.project;
    const size_t substituteBytes=substitute.size()*sizeof(wchar_t),printBytes=print.size()*sizeof(wchar_t);
    std::vector<BYTE> reparse(16+substituteBytes+sizeof(wchar_t)+printBytes+sizeof(wchar_t));
    DWORD tag=0xA0000003;memcpy(reparse.data(),&tag,sizeof(tag));
    WORD fields[]={static_cast<WORD>(reparse.size()-8),0,0,static_cast<WORD>(substituteBytes),static_cast<WORD>(substituteBytes+sizeof(wchar_t)),static_cast<WORD>(printBytes)};
    memcpy(reparse.data()+4,fields,sizeof(fields));memcpy(reparse.data()+16,substitute.c_str(),substituteBytes);memcpy(reparse.data()+16+substituteBytes+sizeof(wchar_t),print.c_str(),printBytes);
    DWORD transferred=0;BOOL planted=::DeviceIoControl(junction,0x000900A4,reparse.data(),static_cast<DWORD>(reparse.size()),nullptr,0,&transferred,nullptr);::CloseHandle(junction);
    require(planted!=FALSE,"junction fixture set failed");
    require(oa_native_open((link+L"\\K").c_str(),GENERIC_READ,FILE_SHARE_READ,FALSE,FALSE,&held)==FALSE,"redirected ancestor admitted");
    for(DWORD stale:{ERROR_FILE_NOT_FOUND,ERROR_PATH_NOT_FOUND}) {
        stale_structural_error=stale;
        ::SetLastError(stale);require(oa_native_open((link+L"\\missing").c_str(),0,FILE_SHARE_READ,TRUE,TRUE,&held)==FALSE,"pending redirected ancestor admitted stale missing error");
        ::SetLastError(stale);require(oa_native_open(link.c_str(),0,FILE_SHARE_READ,TRUE,TRUE,&held)==FALSE,"pending final junction admitted stale missing error");
        ::SetLastError(stale);require(oa_native_open((ordinary+L"\\missing").c_str(),0,FILE_SHARE_READ,TRUE,TRUE,&held)==FALSE,"pending file ancestor admitted stale missing error");
        ::SetLastError(stale);require(oa_native_open(ordinary.c_str(),0,FILE_SHARE_READ,TRUE,TRUE,&held)==FALSE,"pending final wrong kind admitted stale missing error");
    }
    stale_structural_error=0;
    require(::RemoveDirectoryW(link.c_str())!=FALSE,"junction fixture cleanup failed");
    require(::DeleteFileW(ordinary.c_str())!=FALSE,"alias cleanup failed");
    for(const auto &path:paths)require(::DeleteFileW(path.c_str())!=FALSE,"twin cleanup failed");
    std::cout<<"Native installer subset:13 case/Unicode objects, held file/ancestor, pending, aliases and redirect control.\n";
}

}

int main() {
    try {
        oa_identity_path::drive_type_probe = drive_type;
        refused_before_open(L"Y:\\share\\image.png", L"C:\\project", "a mapped drive was not refused");
        refused_before_open(L"\\\\192.0.2.1\\share\\image.png", L"C:\\project", "a UNC path was not refused");
        refused_before_open(L"\\\\.\\pipe\\oa-identity-refused", L"C:\\project", "a device path was not refused");
        refused_before_open(L"C:\\project\\NUL.txt\\image.png", L"C:\\project", "a reserved device component was not refused");
        refused_before_open(L"C:\\project\\COM\u00b9:stream\\image.png", L"C:\\project", "a superscript COM device component was not refused");
        refused_before_open(L"C:\\project\\LPT\u00b2:stream\\image.png", L"C:\\project", "a superscript LPT device component was not refused");
        refused_before_open(L"C:\\project\\image.png", L"Y:\\share", "a mapped folder was not refused");
        native_installer_identity_subset();
        containment_uses_local_file_identity();
        extended_paths_preserve_literal_dot_space_identity();
        std::cout << "LocalPath refusals reached no native open; containment used local file identity.\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
