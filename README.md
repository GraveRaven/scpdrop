## scpDrop
scpDrop is an SCP only SSH server.  
It's purpose is to allow easy transfering of files via SCP without having to worry about users being able to run commands. By default only a single interaction with the service is allowed before a user account is removed. It currently requires scp to be present on the host system but this will in all likelihood change in the future.

### Features
* Password and identity file authentication
* Temporary or permanent users
* Separate or shared content directories
* Maximum upload file size
* Run commands (such as encrypt or compress) on uploaded files.
* Username and password generation.

### Install

Download the package
```
$ go get github.com/graveraven/scpdrop
```
Make sure $PATH includes the $GOBIN path or move scpDrop from $GOBIN to a location within your $PATH.
Copy example_scpdrop.config to either /etc/scpdrop/scpdrop.conf or $HOME/.scpdrop.conf and edit it to your liking.

The server needs an private key to identify itself.
Generate one using ssh-keygen. It's recommended to put the private key in the same folder as the config and make sure it's not world readable.  
The tool does not support passphrases.
```
$ ssh-keygen -t rsa -b 4096 -C scpDrop -f /etc/scpdrop/id_rsa
```

### Usage
```
$ scpdrop -h
Usage: scpdrop server|user
  server
        Start the server
  user
        Add a new user
```

Users are added via the user command. All users are one shot users unless created with the -perm flag.  
If no username is specified a a random 8 character username will be generated.  
If no password is specified one will be prompted for. If no password is entered (press enter) a random 12 character password will be generated. Generated passwords only include upper/lowercase letters and numbers.  
The upsize flag will limit the maximum size of a single file that a user can upload. If set to 0 (default) it will be disabled. This option is best used for temporary users without recursive upload as other users can just upload multiple files.  
The value will be written into the password file as bytes but the parameter can take sizes in human readable form (K,M,G) for example 10M.  
For now the file will still be created on the filesystem but will be empty.  

The -key flag creates an authorized keys template for the user in the keys directory. Do not forget to add the actual key to the file.
```
Usage of User:
  -c string
        Config file path
  -dir string
        Set a users working directory (default "<usersDir>/<username>")
  -down
        Download privileges
  -key
        Create key file template
  -nouserdir
        Make the user use the default up/download dirs
  -p string
        The Password, will be queried or randomized if non is set
  -passfile string
        Output password file
  -perm
        Permanent user
  -plain
        Create a plain text password
  -recdown
        Allow recursive downloads
  -recup
        Allow recursive uploads
  -u string
        The username, will be randomized if non is set
  -up
        Upload privileges
  -upsize string
        Maximum upload size
```

The server command starts the server. It's recommended but not manditory to create a config before running the server.
```
Usage of Server:
  -P string
        Password file
  -c string
        Config file path
  -cmd string
        Command to run on an uploaded file. Filname will be past as the last argument. @filename to run file
  -genpriv
        Generate random private key
  -key string
        Private key location
  -keys string
        Path to keys directory
  -l string
        Listen (default ":2022")
  -log string
        Log level [debug,info,warning,error,none]. Warning: debug will echo passwords to log (default "info")
  -logfile string
        Log filename (use - for stdout) (default stdout)
  -scp string
        Path to scp (default "/usr/bin/scp")
  -shared string
        Path to the shared working directory
  -users string
        Path to where users directories are created
```

#### Config file
The config file will be automatically identified from three places. In order they are
* Current directory
* ~/.config/scpdrop/scpdrop.conf
* /etc/scpdrop/scpdrop.conf

The config settings are newline separated and the values are separated from the config name by one or more spaces or tabs. Hash signs can be used to comment out a line. Note that a hash sign in any other place than at the start of a line will be treated as part of the config file text.
###### Example config
```
Listen :2022
PrivateKey /scpdrop/id_rsa
SharedDir /scpdrop/shared
UsersDir /scpdrop/users
KeysDir /scpdrop/keys
LogLevel info
LogFile /scpdrop/scpdrop.log
PasswdFile /scpdrop/passwd
#Cmd
ScpPath /usr/bin/scp
```

#### Password file
The password file is used for password authentication. It containst the following fields separated by colons.
* Username
* Password hash
* Read/Write permissions
* User directory
* Maximum file size for uploads (in bytes)
* Account type (temporary or permanent)

#### SSH Keys
SSH keys are kept in the keys directory and named after the user (without extension).  files are always permanent and will not be removed.  The comments section is used to describe permissions in the same format as the password file except for the type.

### Security
By design the application is highly restrictive. Unrecognized commands will be denied.  
**Warning**Do not use setuid to allow users to run the service as root. This will cause any user to be able to execute any command as root using the -cmd flag.**\</Warning\>**
