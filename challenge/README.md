# challenge

The `challenge` package provides an interface for and implementations of ACME
challenge performers. Currently supported performers:

* Amazon Web Services (AWS) Route 53.

## AWS Route 53

The following configuration information is needed for the AWS Route 53 performers:

**Account Configuration Information**

* Account region.
* User AccessKeyID
* Use SecretAccessKey

**Route 53 Configuration Information**

* HostedZoneID
* HostedDomainName

**IAM Permissions**

* `route53:ChangeResourceRecordSets`
* `route53:GetChange`
* `route53:ListResourceRecordSets`

A sample policy:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Stmt0000000000000",
            "Effect": "Allow",
            "Action": [
                "route53:GetChange"
            ],
            "Resource": [
                "arn:aws:route53:::change/*"
            ]
        },
        {
            "Sid": "Stmt0000000000001",
            "Effect": "Allow",
            "Action": [
                "route53:ChangeResourceRecordSets",
                "route53:GetHostedZone",
                "route53:ListResourceRecordSets"
            ],
            "Resource": [
                "arn:aws:route53:::hostedzone/Z0000000000000"
            ]
        }
    ]
}
```

## Tests

To run tests against an AWS Route53 performer, a file called
`.roman.configuration` needs to exist the root of the `roman` repo that
contains the above information. An example configuration:

```
Route53-Region=us-east-1
Route53-AccessKeyID=AK000000000000000000
Route53-SecretAccessKey=a000000000000000000000000000000000000000
Route53-HostedZoneID=Z0000000000000
Route53-HostedDomainName=example.com.
```
