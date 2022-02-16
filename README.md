<h1 align="center">MSSQLDecryptor</h1>

<h4 align="center">small and simple decryptor for encrypted objects in Microsoft SQL Server</h4>

------

## Usage instructions:

  - Find the DAC port in your server (usually 1434).
  - If connecting from a remote machine enable remote DAC connections with: `sp_configure 'remote admin connections', 1`
  - Download the latest release or build it yourself.
  - Run the program and give it the object name as an argument

you can run the program with `-help` flag to get more information about the flags
  

## Usage examples:
```bash
# to decrypt dbo.EncryptionTest from 172.20.0.2:1434 and login with dbadmin
./MSSQLDecryptor -host 172.20.0.2 -username dbadmin -dacport 1434 -database Playground dbo.EncryptionTest
# for SQL Server 2008
./MSSQLDecryptor -host 172.20.0.2 -username dbadmin -dacport 1434 -database Playground -disable-encryption dbo.EncryptionTest
```


## How it works:
First it tries to get the encrypted object data from `sys.sysobjvalues` (we need a DAC connection to access this).
The objects are encrypted using the RC4 algorithm and the encryption key is derived from SHA1 hash of
`database family guid + object id + sub object id` and the decrypted source code is stored as UTF16LE.


## Build instructions:

### Prerequisites:
  - [Golang](https://go.dev/dl/)
  
### Build commands:
```bash
git clone https://github.com/er-azh/MSSQLDecryptor
cd MSSQLDecryptor
go mod tidy
go build .
```
you can also install it from source code with `go install github.com/er-azh/MSSQLDecryptor@latest`.
