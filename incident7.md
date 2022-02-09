
# Incident Report '7'

  

Matt, Mohamed, Peter, Rajan, Omozaye | Lighthouse Labs Desk 10

  

Date and time of attack:
Attack start:30/09/2020 10:57:31:00AM
Attack end:30/09/2020 10:57:44:00AM
  
## Vector Diagnosis

1. SQL Injection, Command Injection, Service Side Request Forgery, XXE.

2. Attempted to launch Redis command 'CONFIG GET' command on localhost:6379, to obtain configuration information. Attempted to gain access to meta-data from linklocal address via XXE and SSRF. Attempted to list all operations that the 'information_schema' within SQL DB is making. Attempted to determine XSS vulnerability.

  

## Attack Analysis


*Example of SQL Injection*

```
163.21.64.31 - - [30/Sep/2020:06:57:41 -0400] "GET /index.html?union%20select%201%2C(select(%40)from(select(%40%3A%3D0x00)%2C(select(%40)from(information_schema.processlist)where(%40)in(%40%3A%3Dconcat(%40%2C0x3C62723E%2Cstate%2C0x3a%2Cinfo))))a)%2C3%2C HTTP/1.1" 200 3343 "http://www.cybintnews.com/index.html?%3funion%20select%201%2C(select(%40)from(select(%40%3A%3D0x00)%2C(select(%40)from(information_schema.processlist)where(%40)in(%40%3A%3Dconcat(%40%2C0x3C62723E%2Cstate%2C0x3a%2Cinfo))))a)%2C3%2C" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36"
```

*Decoded SQL Injection*

Below we can see Information_schema.processlist was the target. This contains information on connection identifiers, SQL users, client hosts, DB, command executed, time, and state. 
```
    163.21.64.31--[30/Sep/2020:06:57:41-0400]"GET/index.html?union select 1,(select(@)from(select(@:=0x00),(select(@)from(information_schema.processlist)where(@)in(@:=concat(@,0x3C62723E,state,0x3a,info))))a),3,HTTP/1.1"2003343"http://www.cybintnews.com/index.html??union select 1,(select(@)from(select(@:=0x00),(select(@)from(information_schema.processlist)where(@)in(@:=concat(@,0x3C62723E,state,0x3a,info))))a),3,""Mozilla/5.0(WindowsNT10.0;Win64;x64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/85.0.4183.121Safari/537.36"
```


*Example of XXE / SSRF*

We can see them target linklocal address 169.254.169.254, combined with the AWS specific URI query 'computeMetadata/v1/', we can see that it attempting to perform XXE and SSRF to obtain AWS meta-data. Important information regarding the instance will be exposed.
```
163.21.64.31 - - [30/Sep/2020:06:57:44 -0400] "GET /index.html?url=http://169.254.169.254/computeMetadata/v1/ HTTP/1.1" 200 3343 "http://www.cybintnews.com/index.html?url=http://169.254.169.254/computeMetadata/v1/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36"
```

*Example of Command Inection*
We can see that there is an attempt to outpot 'Cat' the output of the file /etc/passwd, which a file containing the list of users. Cat is a Linux command, and /etc/passwd is a UNIX directory, so the attacker is attempting to target Linux servers and retrieve users through command injection. 
```
72.252.66.221 - - [30/Sep/2020:06:57:43 -0400] "GET /index.html?q=system('cat%20%2fetc%2fpasswd')%3b HTTP/1.1" 200 3343 "http://www.cybintnews.com/index.html?q=system('cat%20%2fetc%2fpasswd')%3b" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36"
```
*Decoded example of command injection*

```
72.252.66.221--[30/Sep/2020:06:57:43-0400]"GET/index.html?q=system('cat /etc/passwd');HTTP/1.1"2003343"http://www.cybintnews.com/index.html?q=system('cat /etc/passwd');""Mozilla/5.0(WindowsNT10.0;Win64;x64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/85.0.4183.121Safari/537.36"
```

**Statistics on attackers**  

IP | Country | Events | URI
--- | --- | --- | --- |
163.21.64.31 | Taiwan | **25** | `union select 1,(select(@)from(select(@:=0x00)`
72.252.66.221 | Guatemala | **20** | `<foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM`
47.36.25.95 | United States | **1** | `url=http://169.254.169.254.xip.io/`

  

## Signature / CVE Details

**CVE-2021-21287**

```
CVE-2021-21287
	
MinIO is a High Performance Object Storage released under Apache License v2.0. In MinIO before version RELEASE.2021-01-30T00-20-58Z there is a server-side request forgery vulnerability. The target application may have functionality for importing data from a URL, publishing data to a URL, or otherwise reading data from a URL that can be tampered with. The attacker modifies the calls to this functionality by supplying a completely different URL or by manipulating how URLs are built (path traversal etc.). In a Server-Side Request Forgery (SSRF) attack, the attacker can abuse functionality on the server to read or update internal resources. The attacker can supply or modify a URL which the code running on the server will read or submit data, and by carefully selecting the URLs, the attacker may be able to read server configuration such as AWS metadata, connect to internal services like HTTP enabled databases, or perform post requests towards internal services which are not intended to be exposed. This is fixed in version RELEASE.2021-01-30T00-20-58Z, all users are advised to upgrade. As a workaround you can disable the browser front-end with "MINIO_BROWSER=off" environment variable.

    CONFIRM:https://github.com/minio/minio/security/advisories/GHSA-m4qq-5f7c-693q
    URL:https://github.com/minio/minio/security/advisories/GHSA-m4qq-5f7c-693q
    MISC:https://github.com/minio/minio/commit/eb6871ecd960d570f70698877209e6db181bf276
    URL:https://github.com/minio/minio/commit/eb6871ecd960d570f70698877209e6db181bf276
    MISC:https://github.com/minio/minio/pull/11337
    URL:https://github.com/minio/minio/pull/11337
    MISC:https://github.com/minio/minio/releases/tag/RELEASE.2021-01-30T00-20-58Z
    URL:https://github.com/minio/minio/releases/tag/RELEASE.2021-01-30T00-20-58Z 

Assigning CNA
GitHub (maintainer security advisories)
Date Record Created
20201222 	Disclaimer: The record creation date may reflect when the CVE ID was allocated or reserved, and does not necessarily indicate when this vulnerability was discovered, shared with the affected vendor, publicly disclosed, or updated in CVE.
Phase (Legacy)
Assigned (20201222)

```
**CVE-2021-23899**

```
CVE-ID
CVE-2021-23899
	
Description
OWASP json-sanitizer before 1.2.2 may emit closing SCRIPT tags and CDATA section delimiters for crafted input. This allows an attacker to inject arbitrary HTML or XML into embedding documents.
References
Note: References are provided for the convenience of the reader to help distinguish between vulnerabilities. The list is not intended to be complete.

    MISC:https://github.com/OWASP/json-sanitizer/commit/a37f594f7378a1c76b3283e0dab9e1ab1dc0247e
    MISC:https://github.com/OWASP/json-sanitizer/compare/v1.2.1...v1.2.2
    MISC:https://groups.google.com/g/json-sanitizer-support/c/dAW1AeNMoA0 

Assigning CNA
MITRE Corporation
Date Record Created
20210112 	Disclaimer: The record creation date may reflect when the CVE ID was allocated or reserved, and does not necessarily indicate when this vulnerability was discovered, shared with the affected vendor, publicly disclosed, or updated in CVE.
Phase (Legacy)
Assigned (20210112)
```
**CVE-2012-5615**

```
CVE-2012-5615
	
Description
Oracle MySQL 5.5.38 and earlier, 5.6.19 and earlier, and MariaDB 5.5.28a, 5.3.11, 5.2.13, 5.1.66, and possibly other versions, generates different error messages with different time delays depending on whether a user name exists, which allows remote attackers to enumerate valid usernames.
References
Note: References are provided for the convenience of the reader to help distinguish between vulnerabilities. The list is not intended to be complete.

    CONFIRM:http://www.oracle.com/technetwork/topics/security/bulletinoct2015-2511968.html
    CONFIRM:http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html
    CONFIRM:https://mariadb.atlassian.net/browse/MDEV-3909
    FULLDISC:20121201 MySQL Remote Preauth User Enumeration Zeroday
    URL:http://seclists.org/fulldisclosure/2012/Dec/9
    GENTOO:GLSA-201308-06
    URL:http://security.gentoo.org/glsa/glsa-201308-06.xml
    MANDRIVA:MDVSA-2013:102
    URL:http://www.mandriva.com/security/advisories?name=MDVSA-2013:102
    MLIST:[oss-security] 20121202 Re: Re: [Full-disclosure] MySQL (Linux) Stack based buffer overrun PoC Zeroday
    URL:http://www.openwall.com/lists/oss-security/2012/12/02/3
    MLIST:[oss-security] 20121202 Re: Re: [Full-disclosure] MySQL (Linux) Stack based buffer overrun PoC Zeroday
    URL:http://www.openwall.com/lists/oss-security/2012/12/02/4
    SECUNIA:53372
    URL:http://secunia.com/advisories/53372
    SUSE:SUSE-SU-2013:0262
    URL:http://lists.opensuse.org/opensuse-security-announce/2013-02/msg00000.html
    SUSE:SUSE-SU-2015:0743
    URL:http://lists.opensuse.org/opensuse-security-announce/2015-04/msg00016.html 

Assigning CNA
Red Hat, Inc.
Date Record Created
20121024 	
Assigned (20121024)
```

## Mitigation Steps

Disable DTD - External entities within HTML5. Ban malicious IPs detected through Splunk 

## Recovery Steps

No data loss

## More Notes 

Conclusion: This majority of the attack is seemingly reconnaissance focused as they attempt to learn more about our servers operating system, internal services, and cloud provider (if applicable) rather than extracting sensitive information. 