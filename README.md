# KeyTabExtract

## Description
KeyTabExtract is a little utility to help extract valuable information from 502 type .keytab files, which may be used to authenticate Linux boxes to Kerberos. The script will extract information such as the realm, Service Principal, Encryption Type and NTLM Hash.

## Usage

`./keytabextract.py [file.keytab]`

## To Do
- Associate keytype values with their encryption type
- Associate Principal Type values with their names
- Add support for 0501 kerberos type files