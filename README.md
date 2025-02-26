### IZ KeyVault

IZ KeyVault is a command line client that manages a key-vault in the users home directory.

This product is functional, but it has internal dependencies to code that is (not yet) in the
public domain.

usage:

See TestSuite

### Usage

#### Create the master seed

This will create the master seed, do this first.

    iz-keyvault master-seed create

#### Create a new profile in your vault

This will create a new profile in your vault

    iz-keyvault identity create --id="alice@atlanta.com" --name="Alice"

#### Create a new ssh-key

This will create a new ssh-key under your profile 

    iz-keyvault ssh-keypair create --id="alice@atlanta.com"

#### Export the ssh-key

This will export you key into your .ssh directory (can overwrite files)

    iz-keyvault ssh-keypair export --id=alice@atlanta.com"

#### Create a new nostr-key

    iz-keyvault nostr-keypair create --id="alice@atlanta.com"

#### Export the nostr-key

     iz-keyvault nostr-keypair export --id="alice@atlanta.com"

#### Create a new openpgp-key

     iz-keyvault openpgp-keypair create --id="alice@atlanta.com"

#### Export the openpgp-key

    iz-keyvault openpgp-keypair export --id="alice@atlanta.com" --password=veryseacret
