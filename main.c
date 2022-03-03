#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <Shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>
#include <direct.h>
#include <strsafe.h>
#include <tchar.h>
#include <json-c/json.h>

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Shlwapi.lib")

#define BLK "\x1b[0;30m"
#define RED "\x1b[0;31m"
#define GRN "\x1b[0;32m"
#define YEL "\x1b[0;33m"
#define BLU "\x1b[0;34m"
#define MAG "\x1b[0;35m"
#define CYN "\x1b[0;36m"
#define WHT "\x1b[0;37m"
#define COLOR_RESET "\x1b[0m"
#define set_color(color) fputs(color, stdout)
#define reset_color()  fputs(COLOR_RESET,stdout)
#define ENABLE_UTF_16() _setmode(_fileno(stdout), 0x20000) //* Enable utf-16 mode for CMD
#define ENABLE_TEXT()   _setmode(_fileno(stdout), 0x4000) //* Rest mode for CMD
#define array_len(array)  (sizeof(array) / sizeof(array[0]))
#define clear() system("cls");
#define title(text) SetConsoleTitleW(L##text)
#define user_name_file "__user_name__.tr"
#define user_domain_file "__user_domain__.tr"
#define jmp goto

void banner();
void terminal_root(char*, char*);
void terminal(char*,char* , char* );
BOOL in_array_char(char* ,char* [],int);
BOOL __CreateFolder(char*, char* );
BOOL __CreateFile(char*, char* );
BOOL __DeleteFile(char*, char* );
BOOL __DeleteFolder(char*, char* );
struct json_object* fetch_path_in_json(WCHAR * path);
BOOL __FileExists(char*, char* );
BOOL IsElevated();
char* getcurrentpath();
char** split(const char* , const char* ) ;
char* wchar_to_char(const wchar_t* pwchar);
char* str_replace(char* orig, char* rep, char* with);
void cd(char*,char*);
void bd(char*);
void ls(char*);
char* get_all_disks();
int ends_with(const char* str, const char* suffix);
void trim(char* str);

int main(int argc,  char* argv[]){
very_start:;
    if (IsElevated()) {
        title("linux theme terminal v0.1 (root)");
    }
    else {
        title("linux theme terminal v0.1 (non-root)");
    }
    clear();
    char* ALL_DISKS = get_all_disks();
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= 0x0004;
    SetConsoleMode(hOut, dwMode);
    char *command = NULL;
    char* current_path = getcurrentpath();
    char* username = NULL;
    char* user_domain = NULL;
    if(!__FileExists(current_path, user_name_file)){
        printf("[%s0%s] Username: ", GRN, COLOR_RESET);
        username = calloc(BUFSIZ,sizeof(char));
        fgets(username, BUFSIZ, stdin);   
        username[strcspn(username, "\n")] = '\0';
        if(__CreateFile(current_path, user_name_file)){
            FILE * username_file = fopen(user_name_file, "w");
            fwrite(username, sizeof(char), strlen(username),username_file);
            fclose(username_file);
        }
        printf("[%s0%s] domain: ", GRN, COLOR_RESET);
        user_domain = calloc(BUFSIZ, sizeof(char));
        fgets(user_domain, BUFSIZ, stdin);
        user_domain[strcspn(user_domain, "\n")] = '\0';
        if (__CreateFile(current_path, user_domain_file)) {
            FILE* domain_file = fopen(user_domain_file, "w");
            fwrite(user_domain, sizeof(char), strlen(user_domain), domain_file);
            fclose(domain_file);
        }

    }else{
        FILE * username_file = fopen(user_name_file, "r");
        fseek(username_file, 0, SEEK_END); 
        size_t file_size_in_bytes = ftell(username_file);
        fseek(username_file, 0, SEEK_SET);
        username = calloc(file_size_in_bytes,sizeof(char));
        char* read_buffer = calloc(file_size_in_bytes+1,sizeof(char));
        if((int)fread(read_buffer,sizeof(char), file_size_in_bytes,username_file) != (int)EOF){
            strcpy(username,read_buffer);
        }
        fclose(username_file);

        FILE* domain_file = fopen(user_domain_file, "r");
        fseek(domain_file, 0, SEEK_END);
        file_size_in_bytes = ftell(domain_file);
        fseek(domain_file, 0, SEEK_SET);
        user_domain = calloc(file_size_in_bytes, sizeof(char));
        free(read_buffer);
        read_buffer = calloc(file_size_in_bytes + 1, sizeof(char));
        if ((int)fread(read_buffer, sizeof(char), file_size_in_bytes, domain_file) != (int)EOF) {
            strcpy(user_domain, read_buffer);
        }
        fclose(domain_file);
    }
    
    char* commands_list[] = {
        "help",
        "ls",
        "mkdir",
        "mkfile",
        "rmfile",
        "rmdir",
        "eduser",
        "eddomain",
        "cd",
        "clear",
        "cls",
        "root",
        "exit"
    };
    char* commands_list_desc[] = {
        "get all commands with it's desc",
        "fetch all files/folders in current dir",
        "create new dir args[] $1 name of dir",
        "create new file args[] $1 name of file",
        "remove\\delete file args[] $1 file name",
        "remove\\delete dir args[] $1 dir name",
        "change the username args[] $1 new username",
        "change the domain args[] $1 new domain",
        "change dir args[] $1 dir",
        "reset the terminal",
        "reset the terminal",
        "turn to root mood",
        "close the terminal"
    };
    int commands_list_size = (int)array_len(commands_list);
    clear();
    _begin_banner:;
    set_color(MAG);
    banner();
    reset_color();
    _begin_terminal:;
    command = calloc(BUFSIZ,sizeof(char));
    if (IsElevated()) {
        terminal_root(username, current_path);
    }
    else {
        terminal(user_domain, username, current_path);
    }
    fgets(command, BUFSIZ, stdin);   
    command[strcspn(command, "\n")] = '\0';
    if (in_array_char(command, commands_list, commands_list_size)){
        if(!strcmp(command, "help")){
            for(int i = 0; i < commands_list_size; i++){
                char* command = commands_list[i];
                char* command_desc = commands_list_desc[i];
                printf("%s%s -> %s%s\n",YEL, command, command_desc,COLOR_RESET);
            }
        }else if(!strcmp(command, "exit")){
            free(command);
            return EXIT_SUCCESS;
        }else if(!strcmp(command, "clear") || !strcmp(command, "cls")){
            clear();
            free(command);
            jmp _begin_banner;
        }else if(strstr(command,"ls") != NULL){
            char** split_command;
            if ((split_command = split(command, " ")) != NULL) {
                if (!strcmp(split_command[0], "ls")) {
                    if (split_command[1] == NULL) {
                        ls(current_path);
                    }
                    else {
                        char* dir_to_fetch = split_command[1];
                        ls(dir_to_fetch);
                    }
                }
            }
        }else if(strstr(command, "mkdir") != NULL){
            char**split_command;
            if((split_command = split(command, " ")) != NULL){
                if (split_command[1] == NULL) {
                    jmp err;
                }
                if(!strcmp(split_command[0], "mkdir")){
                    char* dir_name = split_command[1];
                    if(!__CreateFolder(current_path, dir_name)){
                        printf("[%s-%s] Folder ALREADY_EXISTS !\n",RED,COLOR_RESET);
                    }       
                }else{
                    jmp err;
                }
            }else{
                jmp err;
            }
        }else if(strstr(command, "mkfile") != NULL){
            char**split_command;
            if((split_command = split(command, " ")) != NULL){
                if (split_command[1] == NULL) {
                    jmp err;
                }
                if(!strcmp(split_command[0], "mkfile")){
                    char* file_name = split_command[1];
                    if(!__CreateFile(current_path, file_name)){
                        printf("[%s-%s] File ALREADY_EXISTS !\n",RED,COLOR_RESET);
                    }
                }else{
                    jmp err;
                }
            }else{
                jmp err;
            }
        }else if(strstr(command, "rmfile") != NULL){
            char**split_command;
            if((split_command = split(command, " ")) != NULL){
                if(!strcmp(split_command[0], "rmfile")){
                    char* file_name = split_command[1];
                    if(!__DeleteFile(current_path, file_name)){
                        printf("[%s-%s] Error while delete file !\n",RED,COLOR_RESET);
                    }
                }else{
                    jmp err;
                }
            }else{
                jmp err;
            }
        }else if(strstr(command, "rmdir") != NULL){
            char**split_command;
            if((split_command = split(command, " ")) != NULL){
                if (split_command[1] == NULL) {
                    jmp err;
                }
                if(!strcmp(split_command[0], "rmdir")){
                    char* file_name = split_command[1];
                    if(__DeleteFolder(current_path, file_name) == EOF){
                        printf("[%s-%s] Error while delete folder !\n",RED,COLOR_RESET);
                    }
                }else{
                    jmp err;
                }
            }else{
                jmp err;
            }
        }else if(strstr(command, "eduser") != NULL){
            char**split_command;
            if((split_command = split(command, " ")) != NULL){
                if(!strcmp(split_command[0], "eduser")){
                    if (split_command[1] == NULL) {
                        jmp err;
                    }
                    char* new_username = split_command[1];  
                    new_username[strcspn(new_username, "\n")] = '\0';
                    FILE * username_file = fopen(user_name_file, "w");
                    fwrite(new_username, sizeof(char), strlen(new_username),username_file);
                    fclose(username_file);
                    free(command);

                    jmp very_start;
                }else{
                    jmp err;
                }
            }else{
                jmp err;
            }
        }
        else if (strstr(command, "eddomain") != NULL) {
            char** split_command;
            if ((split_command = split(command, " ")) != NULL) {
                if (!strcmp(split_command[0], "eddomain")) {
                    if (split_command[1] == NULL) {
                        jmp err;
                    }
                    char* new_domain = split_command[1];
                    new_domain[strcspn(new_domain, "\n")] = '\0';
                    FILE* username_file = fopen(user_domain_file, "w");
                    fwrite(new_domain, sizeof(char), strlen(new_domain), username_file);
                    fclose(username_file);
                    free(command);
                    jmp _begin_banner;
                }
                else {
                    jmp err;
                }
            }
            else {
                jmp err;
            }
        }
        else if (strstr(command, "cd") != NULL) {
            char** split_command;
            if ((split_command = split(command, " ")) != NULL) {
                if (!strcmp(split_command[0], "cd")) {
                    if (split_command[1] == NULL) {
                        jmp err;
                    }
                    command += 3;
                    if (!strcmp(command, "..")) {
                        bd(current_path);
                        memset(command, 0, strlen(command));
                        jmp _begin_terminal;
                    }
                    else {
                        char** split_disks = split(ALL_DISKS, "&=");
                        if (ends_with(command, "\\")) {
                            command[strlen(command) - 1] = '\0';
                        }
                        for (int i = 0; ; i++) {
                            char* disk = split_disks[i];
                            if (disk != NULL) {
                                trim(disk);
                                strcat(disk, ":");

                                if (!strcmp(command, disk)) {
                                    strcpy(current_path, command);
                                    jmp _begin_terminal;
                                }
                                else if (strstr(command, disk) != NULL) {
                                    if (PathFileExistsA(command)) {
                                        strcpy(current_path, command);
                                        memset(command, 0, strlen(command));
                                        jmp _begin_terminal;
                                    }

                                }
                            }
                            else {
                                break;
                            }
                            
                        }
                        cd(current_path, command);
                        memset(command, 0, strlen(command));
                        jmp _begin_terminal;
                    }
                    
                }
                else {
                    jmp err;
                }
            }
            else {
                jmp err;
            }
        }
        else if (!strcmp(command, "root")) {
            if (!IsElevated()) {
                char* command = calloc(BUFSIZ, sizeof(char));
                strcat(command, "powershell -Command \"Start-Process '");
                strcat(command, argv[0]);
                strcat(command, "' -Verb runAs\"");
                system(command);
                return EXIT_SUCCESS;
            }
            else {
                printf("[%s+%s] You are root already !\n",GRN, COLOR_RESET);
            }
        }
        free(command);
        jmp _begin_terminal;
        
    }else{ 
        err:;
        printf("[%s!%s] command not found!\n",YEL,COLOR_RESET);
        printf("[%s*%s] use help command =) .\n",MAG,COLOR_RESET);
        free(command);
        jmp _begin_terminal;
    }
    
    return EXIT_SUCCESS;

}

void trim(char* str)
{
    char* ptr = str;
    while (*ptr == ' ' || *ptr == '\t' || *ptr == '\r' || *ptr == '\n') ++ptr;

    char* end = ptr;
    while (*end) ++end;

    if (end > ptr)
    {
        for (--end; end >= ptr && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n'); --end);
    }

    memmove(str, ptr, end - ptr);
    str[end - ptr] = 0;
}

void ls(char* path_name) {
    struct json_object* fetch = fetch_path_in_json(path_name);
    if (fetch != NULL) {
        char* objChar = json_object_to_json_string(fetch);
        if (strstr(objChar, "DIR") != NULL) {
            enum json_type type;
            json_object_object_foreach(fetch, key, val) {
                type = json_object_get_type(val);
                switch (type)
                {
                case json_type_array:
                {
                    struct json_object* arr = json_object_object_get(fetch, "DIR");
                    int count_arr = json_object_array_length(arr);
                    for (int i = 0; i < count_arr; i++)
                    {

                        json_object* element = json_object_array_get_idx(arr, i);
                        char* folder_str = json_object_get_string(element);
                        folder_str[strcspn(folder_str, "?")] = '\0';
                        printf("DIR - %s\n", folder_str);
                    }
                }
                break;
                case json_type_int:
                {
                    char* file_name = key;
                    char* file_path = calloc(MAX_PATH, sizeof(char));
                    strcat(file_path, path_name);
                    if (!ends_with(file_path, "\\")) {
                        strcat(file_path, "\\");
                    }
                    strcat(file_path, file_name);
                    FILE* hFile = fopen(file_path, "r");
                    if (hFile != NULL) {
                        fseek(hFile, 0, SEEK_END);
                        size_t file_size_in_bytes = ftell(hFile);
                        fseek(hFile, 0, SEEK_SET);
                        printf("FILE - SIZE %d Bytes\t%s\n", file_size_in_bytes, file_name);
                        fclose(hFile);
                        free(file_path);
                    }
                }
                break;
                }
            }
        }
        else {
            enum json_type type;
            json_object_object_foreach(fetch, key, val) {
                type = json_object_get_type(key);
                switch (type)
                {
                case json_type_string:
                {
                    char* file_name = key;
                    char* file_path = calloc(MAX_PATH, sizeof(char));
                    strcat(file_path, path_name);
                    if (!ends_with(file_path, "\\")) {
                        strcat(file_path, "\\");
                    }
                    strcat(file_path, file_name);
                    FILE* hFile = fopen(file_path, "r");
                    if (hFile != NULL) {
                        fseek(hFile, 0, SEEK_END);
                        size_t file_size_in_bytes = ftell(hFile);
                        fseek(hFile, 0, SEEK_SET);
                        printf("FILE - SIZE %d Bytes\t%s\n", file_size_in_bytes, file_name);
                        fclose(hFile);
                        free(file_path);
                    }
                }
                break;
                }
            }
        }
    }
}

int ends_with(const char* str, const char* suffix) {
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);

    return (str_len >= suffix_len) &&
        (!memcmp(str + str_len - suffix_len, suffix, suffix_len));
}

char* get_all_disks() {
    TCHAR szDrive[] = _T(" A:");
    char* disk_tag = calloc(1023, sizeof(char));
    strcat(disk_tag, "START&=");
    DWORD uDriveMask = GetLogicalDrives();


    while (uDriveMask)

    {

        if (uDriveMask & 1) {
            strcat(disk_tag, wchar_to_char(szDrive));

            strcat(disk_tag, "&=");

        }
        ++szDrive[1];

        uDriveMask >>= 1;

    }
    strcat(disk_tag, "END");

    return disk_tag;



}

void cd(char* current_path,char* new_dir){
    if (__FileExists(current_path, new_dir)) {
        strcat(current_path, "\\");
        strcat(current_path, new_dir);
    }
    else {
        printf("[%s-%s] Folder not Exists!\n", RED, COLOR_RESET);
    }
}

void bd(char* current_path){
    char** split_path = split(current_path, "\\");
    int i = 0, last_index = 0;
    for (i = 0;; i++) {
        if (split_path[i] == NULL) {
            last_index = i-1;
            break;
        }
    }
    char* last_dir = calloc(strlen(split_path[last_index]) + 2, sizeof(char));
    strcat(last_dir, "\\");
    strcat(last_dir, split_path[last_index]);
    current_path[strlen(current_path) - strlen(last_dir)] = '\0';
    free(last_dir);
}

struct json_object* fetch_path_in_json(char* path) {
    struct json_object* jobj = json_object_new_object();
    json_object* dir_array = json_object_new_array();
    WIN32_FIND_DATA ffd;
    LARGE_INTEGER filesize;
    LPCSTR szDir[MAX_PATH];
    size_t length_of_arg;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    DWORD dwError = 0;


    StringCchLengthA(path, MAX_PATH, &length_of_arg);

    if (length_of_arg > (MAX_PATH - 3))
    {

        return (-1);
    }


    StringCchCopyA(szDir, MAX_PATH, path);
    StringCchCatA(szDir, MAX_PATH, "\\*");

    hFind = FindFirstFileA(szDir, &ffd);

    if (INVALID_HANDLE_VALUE == hFind)
    {

        return NULL;
    }
    do
    {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (
                strcmp(wchar_to_char(ffd.cFileName), ".")
                &&
                strcmp(wchar_to_char(ffd.cFileName), "..")
                )
            {

                char* FolderName = wchar_to_char(ffd.cFileName);
                json_object_array_add(dir_array, json_object_new_string(FolderName));
            }
        }
        else
        {
            filesize.LowPart = ffd.nFileSizeLow;
            filesize.HighPart = ffd.nFileSizeHigh;
            char* FileName = wchar_to_char(ffd.cFileName);

            json_object_object_add(jobj, FileName, json_object_new_int(filesize.QuadPart));

        }
    } while (FindNextFile(hFind, &ffd) != ERROR);
    json_object_object_add(jobj, "DIR", dir_array);

    dwError = GetLastError();
    if (dwError != ERROR_NO_MORE_FILES)
    {
        return NULL;
    }

    FindClose(hFind);
    return jobj;
}

char* str_replace(char* orig, char* rep, char* with) {
    char* result;
    char* ins;
    char* tmp;
    int len_rep;
    int len_with;
    int len_front;
    int count;

    if (!orig || !rep)
        return NULL;
    len_rep = strlen(rep);
    if (len_rep == 0)
        return NULL;
    if (!with)
        with = "";
    len_with = strlen(with);


    ins = orig;
    for (count = 0; tmp = strstr(ins, rep); ++count) {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if (!result)
        return NULL;

    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
    }
    strcpy(tmp, orig);
    return result;
}

char* wchar_to_char(const wchar_t* pwchar)
{
    char szTo[4096];
    szTo[lstrlenW(pwchar)] = '\0';
    WideCharToMultiByte(CP_ACP, 0, pwchar, -1, szTo, (int)lstrlenW(pwchar), NULL, NULL);
    char* chr = _strdup(szTo);
    return chr;
}

BOOL IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}

BOOL __DeleteFolder(char* path, char* name){
    //first Delete the contents of the folder,
//whether it is folders and files .

    char* path_name = calloc(MAX_PATH, sizeof(char));
    strcpy(path_name, path);
    strcat(path_name, "\\");
    strcat(path_name, name);
    //Check if folder is not empty
    if (!PathIsDirectoryEmptyA(path_name)) {
        //fetch folder
        struct json_object* files_in_dir_obj = fetch_path_in_json(path_name);
        if (files_in_dir_obj != NULL) {
            //to check if jsonObject contain dir
            char* objChar = json_object_to_json_string(files_in_dir_obj);
            if (strstr(objChar, "DIR") != NULL) {
                enum json_type type;
                json_object_object_foreach(files_in_dir_obj, key, val) {
                    type = json_object_get_type(val);
                    switch (type)
                    {
                    case json_type_array:
                    {
                        //delete folders
                        struct json_object* arr = json_object_object_get(files_in_dir_obj, "DIR");
                        int count_arr = json_object_array_length(arr);
                        for (int i = 0; i < count_arr; i++)
                        {

                            json_object* element = json_object_array_get_idx(arr, i);
                            char* Folder_str = json_object_get_string(element);
                            if (!PathIsDirectoryEmptyA(Folder_str)) {

                                char reg[MAX_PATH] = "";//regex for folder
                                strcat(reg, path_name);
                                strcat(reg, "\\");
                                strcat(reg, Folder_str);
                                char* folder_to_remove = str_replace(reg, "\\", "/");              
                                folder_to_remove[strlen(folder_to_remove) + 1] = '\0';
                                SHFILEOPSTRUCTW FileOp;
                                ZeroMemory(&FileOp, sizeof(SHFILEOPSTRUCT));
                                FileOp.fFlags = FOF_SILENT | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_NOCONFIRMMKDIR;
                                FileOp.hNameMappings = NULL;
                                FileOp.hwnd = NULL;
                                FileOp.lpszProgressTitle = NULL;
                                FileOp.pFrom = folder_to_remove;
                                FileOp.pTo = NULL;
                                FileOp.wFunc = FO_DELETE;
                                SHFileOperationW(&FileOp); //fast way ShellApi
                            }
                            else {
                                if (RemoveDirectoryW(Folder_str)) {
                                    return TRUE;
                                }
                                else {
                                    return FALSE;

                                }
                            }
                        }
                    }
                    break;
                    case json_type_int/*the int value is for a file key*/:
                    {
                        //delete files
                        char* file_name = key;
                        char reg[MAX_PATH] = "\\\\.\\";//regex for folder
                        strcat(reg, path_name);
                        strcat(reg, "\\");
                        strcat(reg, file_name);
                        if (DeleteFileA(reg)) {}
                        else {
                            return FALSE;
                        }

                    }
                    break;
                    }
                }
                if (RemoveDirectoryA(path_name)) {
                    return TRUE;
                }
                else {
                    return FALSE;
                }
            }
            else {
                enum json_type type;
                json_object_object_foreach(files_in_dir_obj, key, val) {
                    type = json_object_get_type(key);
                    switch (type)
                    {
                    case json_type_string:
                    {
                        //delete files
                        char* file_name = json_object_get_string(files_in_dir_obj, val);
                        if (DeleteFileA(file_name)) {}
                        else {
                            return FALSE;
                        }
                    }
                    break;
                    }
                }
            }
        }
        else {
            return FALSE;
        }
    }
    else {
        if (RemoveDirectoryA(path_name)) {
            return TRUE;
        }
        else {
            return FALSE;
        }
    }
    return FALSE;
}

BOOL __CreateFolder(char* path, char* name){
    char* path_name =  calloc(MAX_PATH,sizeof(char));
    strcpy(path_name,path);
    strcat(path_name, "\\");
    strcat(path_name, name);
    CreateDirectoryA(path_name,NULL);
    if(GetLastError() == ERROR_ALREADY_EXISTS){
        return FALSE;
    }  
    return TRUE;
}

BOOL __DeleteFile(char* path, char* name){
    char* path_name =  calloc(MAX_PATH,sizeof(char));
    strcpy(path_name,path);
    strcat(path_name, "\\");
    strcat(path_name, name);
    return DeleteFileA(path_name);
}

BOOL __FileExists(char* path, char* name){
    char* path_name =  calloc(MAX_PATH,sizeof(char));
    strcpy(path_name,path);
    strcat(path_name, "\\");
    strcat(path_name, name);
    return PathFileExistsA(path_name);
}

BOOL __CreateFile(char* path,char* name){
    char* path_name = calloc(MAX_PATH,sizeof(char));
    strcpy(path_name,path);
    strcat(path_name, "\\");
    strcat(path_name, name);
    HANDLE hFile = CreateFileA(path_name,
                    GENERIC_READ | GENERIC_WRITE,
                        (int)NULL,
                            NULL,
                                CREATE_NEW,
                                    FILE_ATTRIBUTE_NORMAL,
                                        NULL);
    if(GetLastError() == ERROR_ALREADY_EXISTS || GetLastError() == ERROR_FILE_EXISTS){
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);
    return TRUE;
}

char** split(const char* str, const char* delim) {
	char* s = _strdup(str);
	if (strtok(s, delim) == 0) {
		return NULL;
	}
	int nw = 1;
	while (strtok(NULL, delim) != 0)
		nw += 1;
	strcpy(s, str);
	char** v = malloc((nw + 1) * sizeof(char*));
	int i;
	v[0] = _strdup(strtok(s, delim));
	for (i = 1; i != nw; ++i) {
		v[i] = _strdup(strtok(NULL, delim));
	}
	v[i] = NULL;
	free(s);
	return v;
}

char* getcurrentpath(){
    char *__$PATH = (char *)calloc(MAX_PATH,sizeof(char));
    return _getcwd(__$PATH,MAX_PATH);
}

BOOL in_array_char(char* element,char* array[],int size){ 

    for(int i = 0; i < size; i++){
        char* index = array[i];
        if(!strcmp(element, index)){
            return TRUE;
        }else if(strstr(element, index) != NULL){
            char** split_command;
            if ((split_command = split(element, " ")) != NULL) {
                if (!strcmp(split_command[0], index)) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

void terminal_root(char* user, char* path){
    ENABLE_UTF_16();
    wprintf(L"┌──(");ENABLE_TEXT();printf("%sroot@%s%s)-[%s]\n", RED,user,COLOR_RESET,path);
    ENABLE_UTF_16();
    wprintf(L"└─$");
    ENABLE_TEXT();

}

void terminal(char*domain, char*user, char*path) {
    ENABLE_UTF_16();
    wprintf(L"┌──("); ENABLE_TEXT(); printf("%s%s@%s%s)-[%s]\n", BLU, domain, user, COLOR_RESET, path);
    ENABLE_UTF_16();
    wprintf(L"└─$");
    ENABLE_TEXT();
}

void banner(){
    ENABLE_UTF_16();
    wprintf(L"·▄▄▄▄  ▄▄▄ . ▌ ▐·▪  ▄▄▌  \n");
    wprintf(L"██▪ ██ ▀▄.▀·▪█·█▌██ ██•  \n");
    wprintf(L"▐█· ▐█▌▐▀▀▪▄▐█▐█•▐█·██▪  \n");
    wprintf(L"██. ██ ▐█▄▄▌ ███ ▐█▌▐█▌▐▌\n");
    wprintf(L"▀▀▀▀▀•  ▀▀▀ . ▀  ▀▀▀.▀▀▀ \n");
    ENABLE_TEXT();
}
