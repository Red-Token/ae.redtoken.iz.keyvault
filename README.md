### IZ KeyVault

IZ KeyVault is a pragmatic key generator written in java. It currently runs on Linux but should in theory run on both
Windows and macOS. The idee is to have a system that allows the user to manage his keys in a simple and unified way. The
principal is pretty simple. First you generate a master seed, this one should be saved in /tmp then stored in a very
safe place. Then you use this key to generate a sub-key this is stored in the users home, per default this is
'~/.config/iz-keyvault/'. Then you can create an id, like alice@atlanta.com. From this id you then generate keys for
different protocols. Currently, we support openpgp, ssh and nostr. If you need your key on another computer you simply
move your seed there. The master seed will always be able to regenerate all the keys.

### Building
To build the tool simply use mvn

    mvn package

### Usage

#### Create the master seed

This will create the master seed, do this first. We place it in the temp folder. Make sure to save it in a secure place

    iz-keyvault master-seed create --master-seed-file /tmp/master-seed

#### Create the sub seed

This will create the sub seed. This is the seed we will use to create all of your keys.

    iz-keyvault sub-seed create --master-seed-file /tmp/master-seed

#### Create a new profile in your vault

This will create a new profile in your vault

    iz-keyvault identity create --id="alice@atlanta.com" --name="Alice"

#### Create a new ssh-key

This will create a new ssh-key under your profile

    iz-keyvault ssh-keypair create 

#### Export the ssh-key

This will export you key into your .ssh directory (can overwrite files)

    iz-keyvault ssh-keypair export

#### Create a new nostr-key

    iz-keyvault nostr-keypair create

#### Export the nostr-key

     iz-keyvault nostr-keypair export

#### Create a new openpgp-key

     iz-keyvault openpgp-keypair create

#### Export the openpgp-key

    iz-keyvault openpgp-keypair export --password=veryseacret
