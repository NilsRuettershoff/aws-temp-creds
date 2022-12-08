# aws-temp-creds

I wrote this tool as some tools like terraform are not able to handle assume roles with MFA well

Hence you can create with this tool temporary credentials, which are written to the aws credentials file

in case you have special characters in your username you need to set a custom session name as sts assume-role interface does not allow special characters.