package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/hashicorp/vault/shamir"
	"google.golang.org/protobuf/proto"
)

var supportedBackends = []string{"file", "consul"}

func isBackendSupported(name string) bool {
	for _, v := range supportedBackends {
		if name == v {
			return true
		}
	}
	return false
}

func DecryptEnvelop(data *EnvelopeInfo) ([]byte, error) {
	aesCipher, err := aes.NewCipher(data.Key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, data.Iv, data.Ciphertext, nil)
}

func RecoveryKey(b BackendProvider, k KMSProvider) ([]byte, error) {
	data, err := b.GetRecoveryKey()
	if err != nil {
		panic(err)
	}

	//EncryptedBlobInfo
	encryptedBlob := &EncryptedBlobInfo{}
	err = proto.Unmarshal(data, encryptedBlob)
	if err != nil {
		panic(err)
	}

	// Decrypt Data Encryption Key (DEK)
	dek, err := k.Decrypt(encryptedBlob.KeyInfo.GetWrappedKey())
	if err != nil {
		panic(err)
	}

	encryptedData := &EnvelopeInfo{
		Ciphertext: encryptedBlob.Ciphertext,
		Key:        dek,
		Iv:         encryptedBlob.Iv,
	}

	return DecryptEnvelop(encryptedData)
}

func do(c *cli.Context) error {
	backendName := c.String("backend")

	var filePath string
	var err error
	var backend BackendProvider
	if backendName == "file" {
		filePath = c.String("file-path")
		if filePath == "" {
			return fmt.Errorf("Please specify filesystem path (--file-path)")
		}
		backend, err = NewFileBackend(filePath)
		if err != nil {
			return err
		}
	}

	if backendName == "consul" {
		consulAddr := c.String("consul-address")
		consulPath := c.String("consul-path")
		backend, err = NewConsulBackend(consulAddr, consulPath)
		if err != nil {
			return err
		}
	}

	keyID := c.String("aws-access-key-id")
	secret := c.String("aws-secret-access-key")
	token := c.String("aws-session-token")
	profile := c.String("aws-profile")
	region := c.String("aws-region")
	recoveryShares := c.Int("recovery-shares")
	recoveryThreshold := c.Int("recovery-threshold")

	if recoveryThreshold > recoveryShares {
		log.Fatalf("Recovery threshold (%q) must be less than or equal to recovery shares (%q)", recoveryThreshold, recoveryShares)
	}

	kms, err := NewAWSKMS(&AWSConfig{
		Region:          region,
		Profile:         profile,
		AccessKeyID:     keyID,
		SecretAccessKey: secret,
		SessionToken:    token,
	})
	if err != nil {
		panic(err)
	}

	plain, err := RecoveryKey(backend, kms)
	if err != nil {
		return err
	}

	// Getting from reconvery config
	if recoveryShares == 0 && recoveryThreshold == 0 {
		conf, err := backend.RecoveryConfig()
		if err != nil {
			return err
		}
		recoveryShares = conf.SecretShares
		recoveryThreshold = conf.SecretThreshold
	}

	if recoveryShares == 1 && recoveryThreshold == 1 {
		fmt.Printf("Recovery Key: %s\n", base64.StdEncoding.EncodeToString(plain))
		return nil
	}

	shared, err := shamir.Split(plain, recoveryShares, recoveryThreshold)
	if err != nil {
		return err
	}
	for i, key := range shared {
		fmt.Printf("Recovery Key %d: %s\n", i+1, base64.StdEncoding.EncodeToString(key))
	}
	return nil
}

func main() {
	app := &cli.App{
		Usage: "Misc for fun",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:        "recovery-shares",
				Usage:       "Number of key shares to split the recovery key into",
				Value:       0,
				DefaultText: "Automatically fetch from saved recovery config",
			},
			&cli.IntFlag{
				Name:        "recovery-threshold",
				Usage:       "Number of key shares required to reconstruct the recovery key",
				Value:       0,
				DefaultText: "Automatically fetch from saved recovery config",
			},
			&cli.StringFlag{
				Name:        "backend",
				Usage:       "storage backend name (file/consul)",
				Value:       "file",
				DefaultText: "file",
			},
			&cli.StringFlag{
				Name:        "consul-address",
				Usage:       "Specifies the address of the Consul agent to communicate with.",
				Value:       "http://127.0.0.1:8500",
				DefaultText: "http://127.0.0.1:8500",
			},
			&cli.StringFlag{
				Name:        "consul-path",
				Usage:       "Specifies the path in Consul's key-value store where Vault data will be stored (Default: 'vault/')",
				Value:       "vault/",
				DefaultText: "vault/",
			},
			&cli.StringFlag{
				Name:  "file-path",
				Usage: " The absolute path on disk to the directory where the data will be stored",
				Value: "",
			},
			&cli.StringFlag{
				Name:        "aws-access-key-id",
				Usage:       "AWS Access Key ID",
				Value:       "",
				DefaultText: "",
			},
			&cli.StringFlag{
				Name:        "aws-secret-access-key",
				Usage:       "AWS Secret Access Key",
				Value:       "",
				DefaultText: "",
			},
			&cli.StringFlag{
				Name:        "aws-session-token",
				Usage:       "AWS Session Token",
				Value:       "",
				DefaultText: "",
			},
			&cli.StringFlag{
				Name:  "aws-region",
				Usage: "AWS Region",
				Value: "eu-west-1",
			},
			&cli.StringFlag{
				Name:        "aws-profile",
				Usage:       "AWS Profile name",
				Value:       "",
				DefaultText: "",
			},
		},
		Action: do,
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
