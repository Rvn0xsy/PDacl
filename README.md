# PDacl

Play Doh Windows ACL Tools

����Ķ���[WindowsȨ�޿�����صķ����빥������](https://payloads.online/archivers/2021-01-31/1)

## Introduction

PDAcl ��һ��֧��Windows�Ŀ¼��չȨ�����á�Windows�Ŀ¼����Ȩ�����á�Windows����Ȩ�����õ�����ߡ�

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

### ���DCSyncȨ��

```
PDAcl.exe ADE -a -u domain\user1 -e DS-Replication-Get-Changes -s DC=domain,DC=com
```

### �Ƴ�DCSyncȨ��


```
PDAcl.exe ADE -r -u domain\user1 -e DS-Replication-Get-Changes -s DC=domain,DC=com
```

### ��Ӽ�����޸�Ȩ��

```
PDAcl.exe AD -a -s CN=John-PC,CN=Computers,DC=Domain,DC=com -e ADS-Right-Generic-Write -u domain\user1
```

### ��������û����޸ĵķ���Ȩ��

```
PDAcl.exe SC -a -s ServiceName -e Service-All-Access -u Everyone
```