## assumerole

This python package was inspired by the GO implementation of [assume-role](https://github.com/remind101/assume-role).
This utility makes it easier to switch between multiple AWS profiles.


### Pre-requisite
- aws sdk should be installed
- aws credentials are provided under ~/.aws/credentials
- all the aws profiles are created correctly under ~/.aws/config

This utility uses sts utility within the [boto3 package](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sts.html).
You can learn more about sts command under [awscli](https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role.html)


### Installation:
```pip install --index-url https://test.pypi.org/simple/  assumerole```
For updating existing package use
```pip install -U --index-url https://test.pypi.org/simple/  assumerole```


### Usage
```assume --profile <aws-profile-name>```
or
```assume -p <aws-profile-name>```

You may be prompted to pass your MFA code if its required

By default, the tokens returned are cached under the folder ```~/.aws/cached_tokens```
Only if the token has expired, will new tokens be requested from AWS.
You can also find a history of all successful commands in the file ```~/.aws/assume_role_history```

In case you do not want to use your cached tokens use the optional refresh parameter

```assume --profile <aws-profile-name> --refresh``` or
```assume -p <aws-profile-name> -r```


In case you do not want to set the expirty time on the token optional duration parameter
Default is 8 hours and maximum value is 12 (set by AWS)

```assume --profile <aws-profile-name> --duration 10``` or
```assume -p <aws-profile-name> -d 10```


### TODO:
- Perform comprehensive coverage testing. Once package is tested fully, it will be made available in pypi.org
- In the meantime, do test it out and feel free to submit PRs

