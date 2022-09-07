# PDacl

Play Doh Windows ACL Tools

相关阅读：[Windows权限控制相关的防御与攻击技术](https://payloads.online/archivers/2021-01-31/1)

## Introduction

PDAcl 是一个支持Windows活动目录扩展权限设置、Windows活动目录常规权限设置、Windows服务权限设置的命令工具。

```
PS C:\> .\PDAcl.exe -h
Play Doh Windows ACL Tools. - By Rvn0xsy
[@] Blog : https://payloads.online/
Usage: C:\PDAcl.exe [OPTIONS] SUBCOMMAND

Options:
  -h,--help                   Print this help message and exit

Subcommands:
  ADE                         ActiveDirectory ExtendRights
  AD                          ActiveDirectory Rights
  SC                          Service Rights



PS C:\> .\PDAcl.exe ADE -h
ActiveDirectory ExtendRights
Usage: C:\PDAcl.exe ADE [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  -a,--add                    Add Right to Object.
  -r,--remove                 Remove ActiveDirectory ExtendedRight
  -u,--user TEXT              Username,e.g. DomainName\Rvn0xsy.
  -e,--extended-right TEXT    ActiveDirectory ExtendedRight
  -s,--server TEXT            ActiveDirectory Server LDAP Path.
  --list                      List All ActiveDirectory ExtendedRights .
  --login TEXT                Login Use,e.g. Domain/Username@Password

```

## Usage

### 添加DCSync权限

```
PDAcl.exe ADE -a -u domain\user1 -e DS-Replication-Get-Changes -s DC=domain,DC=com
```

### 移除DCSync权限


```
PDAcl.exe ADE -r -u domain\user1 -e DS-Replication-Get-Changes -s DC=domain,DC=com
```

### 添加计算机修改权限

```
PDAcl.exe AD -a -s CN=John-PC,CN=Computers,DC=Domain,DC=com -e ADS-Right-Generic-Write -u domain\user1
```

### 添加任意用户可修改的服务权限

```
PDAcl.exe SC -a -s ServiceName -e Service-All-Access -u Everyone
```