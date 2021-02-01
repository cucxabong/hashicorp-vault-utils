package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

type KMSProvider interface {
	Decrypt([]byte) ([]byte, error)
}

type AWSConfig struct {
	SharedCredsFileName string
	Profile             string
	AccessKeyID         string
	SecretAccessKey     string
	SessionToken        string
	Region              string
}

type AWSKMS struct {
	Client *kms.KMS
}

func NewAWSKMS(c *AWSConfig) (KMSProvider, error) {
	providers := []credentials.Provider{
		&credentials.EnvProvider{},
		&credentials.SharedCredentialsProvider{
			Profile:  c.Profile,
			Filename: c.SharedCredsFileName,
		},
		&credentials.StaticProvider{
			Value: credentials.Value{
				AccessKeyID:     c.AccessKeyID,
				SecretAccessKey: c.SecretAccessKey,
				SessionToken:    c.SessionToken,
			},
		},
	}

	creds := credentials.NewChainCredentials(providers)

	sess, err := session.NewSession(&aws.Config{
		Credentials: creds,
		Region:      aws.String(c.Region),
	})
	if err != nil {
		return nil, err
	}

	kms := &AWSKMS{
		Client: kms.New(sess),
	}

	return kms, nil
}

func (k *AWSKMS) Decrypt(cipher []byte) ([]byte, error) {
	input := &kms.DecryptInput{
		CiphertextBlob: cipher,
	}

	output, err := k.Client.Decrypt(input)
	if err != nil {
		return nil, err
	}

	return output.Plaintext, nil
}
