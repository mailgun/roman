package challenge

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/context"
)

type Route53 struct {
	Region           string
	AccessKeyID      string
	SecretAccessKey  string
	HostedZoneID     string
	HostedDomainName string
	WaitForSync      bool
}

// Perform will perform the challenge against an acmeClient.
func (r Route53) Perform(acmeClient *acme.Client, authorization *acme.Authorization, hostname string) error {
	// get a route53 client that can perform crud actions against route53
	r53, err := newRoute53Client(r)
	if err != nil {
		return err
	}

	// extract the dns challenge from the authorization
	challenge, err := getChallenge(authorization)
	if err != nil {
		return err
	}

	// challengeValue create from the token, it's a fingerprint of your public key
	// and the token, hashed, then base64 encoded.
	challengeValue, err := acmeClient.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		return err
	}

	// update dns record with challenge value
	err = r53.Upsert(hostname, challengeValue)
	if err != nil {
		return fmt.Errorf("unexpected response from DNS upserter: %v", err)
	}

	// the interaction with the acme server should not take longer than 10 minutes
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// notify acme server that you've updated dns
	_, err = acmeClient.Accept(ctx, challenge)
	if err != nil {
		return fmt.Errorf("unexpected response from acmeClient.Accept: %v", err)
	}

	// wait for acme sever to response
	_, err = acmeClient.WaitAuthorization(ctx, authorization.URI)
	if err != nil {
		return err
	}

	// remove the record so we don't pollute dns
	err = r53.Delete(hostname, challengeValue)
	if err != nil {
		return err
	}

	return nil
}

// getChallenge checks if the authorization contains a challenge that can be performed,
// and if one is found, it is also returned.
func getChallenge(authorization *acme.Authorization) (*acme.Challenge, error) {
	var c *acme.Challenge

	for _, v := range authorization.Challenges {
		if v.Type == DNSChallenge {
			c = v
			break
		}
	}
	if c == nil {
		return c, fmt.Errorf("%v challenge type not in list of supported challenges: %v", DNSChallenge, authorization.Challenges)
	}

	return c, nil
}

type route53Client struct {
	sess         *session.Session
	hostedZoneID string
	waitForSync  bool
}

func newRoute53Client(c Route53) (*route53Client, error) {
	// create config with passed in credentials and region
	cfg := &aws.Config{
		Region: aws.String(c.Region),
		Credentials: credentials.NewChainCredentials([]credentials.Provider{
			&credentials.StaticProvider{
				Value: credentials.Value{
					AccessKeyID:     c.AccessKeyID,
					SecretAccessKey: c.SecretAccessKey,
				},
			},
			&credentials.EnvProvider{},
			&credentials.SharedCredentialsProvider{},
		}),
	}

	// create an aws session with above config
	sess, err := session.NewSession(cfg)
	if err != nil {
		return nil, err
	}

	return &route53Client{sess, c.HostedZoneID, c.WaitForSync}, nil
}

func (r route53Client) Upsert(hostname string, challengeValue string) error {
	svc := route53.New(r.sess)

	challengeValue = fmt.Sprintf(`"%v"`, challengeValue)
	recordName := fmt.Sprintf("%v.%v.", ACMEChallengePrefix, hostname)

	// prepare upsert request
	input := &route53.ChangeResourceRecordSetsInput{
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{
				{
					Action: aws.String(route53.ChangeActionUpsert),
					ResourceRecordSet: &route53.ResourceRecordSet{
						Name: aws.String(recordName),
						Type: aws.String(route53.RRTypeTxt),
						ResourceRecords: []*route53.ResourceRecord{
							{
								Value: aws.String(challengeValue),
							},
						},
						TTL: aws.Int64(300),
					},
				},
			},
		},
		HostedZoneId: aws.String(r.hostedZoneID),
	}

	// perform the upsert request
	output, err := svc.ChangeResourceRecordSets(input)
	if err != nil {
		return err
	}

	if r.waitForSync {
		// wait for upsert to sync with a timeout of 30 minutes which is
		// what amazon says is the maximum time a request will take to sync.
		timeoutChannel := time.After(30 * time.Minute)
		for {
			select {
			case <-timeoutChannel:
				return fmt.Errorf("timed out waiting for DNS to sync")
			default:
				// check if upsert has synced
				in := &route53.GetChangeInput{
					Id: output.ChangeInfo.Id,
				}
				out, err := svc.GetChange(in)
				if err != nil {
					return err
				}

				// if it has break out
				if *out.ChangeInfo.Status == route53.ChangeStatusInsync {
					goto success
				}

				// wait and try again
				time.Sleep(30 * time.Second)
			}
		}
	}

success:
	return nil
}

func (r route53Client) Read(hostname string) (string, error) {
	svc := route53.New(r.sess)

	recordName := fmt.Sprintf("%v.%v.", ACMEChallengePrefix, hostname)

	// prepare read request
	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(r.hostedZoneID),
		MaxItems:        aws.String("1"),
		StartRecordName: aws.String(recordName),
		StartRecordType: aws.String(route53.RRTypeTxt),
	}

	// perform read request
	output, err := svc.ListResourceRecordSets(input)
	if err != nil {
		return "", err
	}

	// validate output
	if len(output.ResourceRecordSets) < 1 {
		return "", fmt.Errorf("found 0 Record Sets")
	}
	rrs := output.ResourceRecordSets[0]

	// validate output
	if len(rrs.ResourceRecords) < 1 {
		return "", fmt.Errorf("found 0 Records")
	}
	rr := rrs.ResourceRecords[0]

	return strings.Trim(*rr.Value, `"`), nil
}

func (r route53Client) Delete(hostname string, challengeValue string) error {
	svc := route53.New(r.sess)

	challengeValue = fmt.Sprintf(`"%v"`, challengeValue)
	recordName := fmt.Sprintf("%v.%v.", ACMEChallengePrefix, hostname)

	// prepare delete request
	input := &route53.ChangeResourceRecordSetsInput{
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{
				{
					Action: aws.String(route53.ChangeActionDelete),
					ResourceRecordSet: &route53.ResourceRecordSet{
						Name: aws.String(recordName),
						Type: aws.String(route53.RRTypeTxt),
						ResourceRecords: []*route53.ResourceRecord{
							{
								Value: aws.String(challengeValue),
							},
						},
						TTL: aws.Int64(300),
					},
				},
			},
		},
		HostedZoneId: aws.String(r.hostedZoneID),
	}

	// perform the delete request
	output, err := svc.ChangeResourceRecordSets(input)
	if err != nil {
		// if the error was not found, return success
		if strings.Contains(err.Error(), "not found") {
			goto success
		}

		return err
	}

	if r.waitForSync {
		// wait for delete to sync with a timeout of 30 minutes which is
		// what amazon says is the maximum time a request will take to sync.
		timeoutChannel := time.After(30 * time.Minute)
		for {
			select {
			case <-timeoutChannel:
				return fmt.Errorf("timed out waiting for DNS to sync")
			default:
				// check if delete has synced
				in := &route53.GetChangeInput{
					Id: output.ChangeInfo.Id,
				}
				out, err := svc.GetChange(in)
				if err != nil {
					return err
				}

				// if it has break out
				if *out.ChangeInfo.Status == route53.ChangeStatusInsync {
					goto success
				}

				// wait and try again
				time.Sleep(30 * time.Second)
			}
		}
	}

success:
	return nil
}
