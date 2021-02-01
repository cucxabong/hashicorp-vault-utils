Intro
====
This tool is a demonstration of [my blog post](https://dev.to/cucxabong/recover-hashicorp-vault-recovery-key-1343). It's allow us fetching encrypted Vault recovery key from storage backend (filesystem/consul supported at the moment) and decrypt it with AWS KMS.

Feature
====
* Getting encrypted recovery key from local filesystem and consul
* Decrypt recovery key with AWS KMS service

Example
=====
```
hashicorp-vault-utils --aws-profile dev --backend file --file-path /data/vault
```

Usage
====
```
NAME:
   hashicorp-vault-utils - Misc for fun

USAGE:
   hashicorp-vault-utils [global options] command [command options] [arguments...]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --backend value                storage backend name (file/consul) (default: file)
   --consul-address value         Specifies the address of the Consul agent to communicate with. (default: http://127.0.0.1:8500)
   --consul-path value            Specifies the path in Consul's key-value store where Vault data will be stored (Default: 'vault/') (default: vault/)
   --file-path value              The absolute path on disk to the directory where the data will be stored
   --aws-access-key-id value      AWS Access Key ID
   --aws-secret-access-key value  AWS Secret Access Key
   --aws-session-token value      AWS Session Token
   --aws-region value             AWS Region (default: "eu-west-1")
   --aws-profile value            AWS Profile name
   --help, -h                     show help (default: false)
```
