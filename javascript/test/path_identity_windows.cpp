#define OA_IDENTITY_PATH_TESTING
#include "../path_identity_windows.h"

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
        containment_uses_local_file_identity();
        extended_paths_preserve_literal_dot_space_identity();
        std::cout << "LocalPath refusals reached no native open; containment used local file identity.\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
