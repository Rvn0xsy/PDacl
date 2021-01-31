# PDacl

Play Doh Windows ACL Tools

相关阅读：

## Introduction

PDAcl 是一个支持Windows活动目录扩展权限设置、Windows活动目录常规权限设置、Windows服务权限设置的命令工具。

```
C:\>PDAcl.exe -h
Play Doh Windows ACL Tools. - By Rvn0xsy
[@] Blog : https://payloads.online/
Usage: C:\PDAcl.exe [OPTIONS] SUBCOMMAND

Options:
  -h,--help                   Print this help message and exit

Subcommands:
  AD-ExtendRights             ActiveDirectory ExtendRights
  AD-Rights                   ActiveDirectory Rights
  Service                     Service Rights


C:\>PDAcl.exe AD-ExtendRights -h
ActiveDirectory ExtendRights
Usage: C:\PDAcl.exe AD-ExtendRights [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  -a,--add                    Add Right to Object.
  -r,--remove                 Remove ActiveDirectory ExtendedRight
  -u,--user TEXT              Username,e.g. DomainName\Rvn0xsy.
  -e,--extended-right TEXT    ActiveDirectory ExtendedRight
  -s,--server TEXT            ActiveDirectory Server LDAP Path.
  -l,--list                   List All ActiveDirectory ExtendedRights .
```

## Usage

### 添加DCSync权限

```
PDAcl.exe AD-ExtendRights -a -u domain\user1 -e DS-Replication-Get-Changes -s DC=domain,DC=com
```

### 移除DCSync权限


```
PDAcl.exe AD-ExtendRights -r -u domain\user1 -e DS-Replication-Get-Changes -s DC=domain,DC=com
```

### 添加计算机修改权限

```
PDAcl.exe AD-Rights -a -s CN=John-PC,CN=Computers,DC=Domain,DC=com -e ADS-Right-Generic-Write -u domain\user1
```

### 添加任意用户可修改的服务权限

```
PDAcl.exe Service -a -s ServiceName -e Service-All-Access -u Everyone
```

## Rights List

### AD-ExtendRights

```
[*] Abandon-Replication
[*] Add-GUID
[*] Allocate-Rids
[*] Allowed-To-Authenticate
[*] Apply-Group-Policy
[*] Certificate-Enrollment
[*] Change-Domain-Master
[*] Change-Infrastructure-Master
[*] Change-PDC
[*] Change-Rid-Master
[*] Change-Schema-Master
[*] Create-Inbound-Forest-Trust
[*] DS-Check-Stale-Phantoms
[*] DS-Clone-Domain-Controller
[*] DS-Execute-Intentions-Script
[*] DS-Install-Replica
[*] DS-Query-Self-Quota
[*] DS-Replication-Get-Changes
[*] DS-Replication-Get-Changes-All
[*] DS-Replication-Get-Changes-In-Filtered-Set
[*] DS-Replication-Manage-Topology
[*] DS-Replication-Monitor-Topology
[*] DS-Replication-Synchronize
[*] Do-Garbage-Collection
[*] Domain-Administer-Server
[*] Enable-Per-User-Reversibly-Encrypted-Password
[*] Generate-RSoP-Logging
[*] Generate-RSoP-Planning
[*] Manage-Optional-Features
[*] Migrate-SID-History
[*] Open-Address-Book
[*] Read-Only-Replication-Secret-Synchronization
[*] Reanimate-Tombstones
[*] Recalculate-Hierarchy
[*] Recalculate-Security-Inheritance
[*] Receive-As
[*] Refresh-Group-Cache
[*] Reload-SSL-Certificate
[*] Run-Protect-Admin-Groups-Task
[*] SAM-Enumerate-Entire-Domain
[*] Send-As
[*] Send-To
[*] Unexpire-Password
[*] Update-Password-Not-Required-Bit
[*] Update-Schema-Cache
[*] User-Change-Password
[*] User-Force-Change-Password
[*] msmq-Open-Connector
[*] msmq-Peek
[*] msmq-Peek-Dead-Letter
[*] msmq-Peek-computer-Journal
[*] msmq-Receive
[*] msmq-Receive-Dead-Letter
[*] msmq-Receive-computer-Journal
[*] msmq-Receive-journal
[*] msmq-Send
```

### AD-Rights

```
[*] ADS-Right-Access-System-Security
[*] ADS-Right-Actrl-Ds-List
[*] ADS-Right-Delete
[*] ADS-Right-Ds-Control-Access
[*] ADS-Right-Ds-Create-Child
[*] ADS-Right-Ds-Delete-Child
[*] ADS-Right-Ds-Delete-Tree
[*] ADS-Right-Ds-List-Object
[*] ADS-Right-Ds-Read-Prop
[*] ADS-Right-Ds-Self
[*] ADS-Right-Ds-Write-Prop
[*] ADS-Right-Generic-All
[*] ADS-Right-Generic-Execute
[*] ADS-Right-Generic-Read
[*] ADS-Right-Generic-Write
[*] ADS-Right-Red-Control
[*] ADS-Right-Synchronize
[*] ADS-Right-Write-DAC
[*] ADS-Right-Write-Owner
```

### Service Rights

```
[*] Access-System-Security
[*] Delete
[*] Generic-Execute
[*] Generic-Read
[*] Generic-Write
[*] Read-Control
[*] Service-All-Access
[*] Service-Change-Config
[*] Service-Enumerate-Dependents
[*] Service-Interrogate
[*] Service-Pause-Continue
[*] Service-Query-Config
[*] Service-Query-Status
[*] Service-Start
[*] Service-Stop
[*] Service-User-Defined-Control
[*] Write-Dac
[*] Write-Owner
```