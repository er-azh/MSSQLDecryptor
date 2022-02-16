package main

import (
	"crypto/rc4"
	"crypto/sha1"
	"database/sql"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"syscall"

	"golang.org/x/term"
	"golang.org/x/text/encoding/unicode"

	_ "github.com/denisenkom/go-mssqldb"
)

// gets an object's id from its name. returns an error if OBJECT_ID returns NULL
func getObjectID(db *sql.DB, objectName string) (out uint32, err error) {
	row := db.QueryRow("SELECT OBJECT_ID(:1)", objectName)
	if row.Err() != nil {
		return 0, row.Err()
	}
	val := sql.NullInt64{}
	err = row.Scan(&val)
	if err != nil {
		return
	}
	if val.Valid {
		out = uint32(val.Int64)
	} else {
		err = errors.New("object name invalid or not found")
	}
	return
}

// gets the database family GUID as binary. we'll use this to calculate the RC4 key
func getDbFamilyGUID(db *sql.DB) (out []byte, err error) {
	row := db.QueryRow("SELECT CONVERT(binary(16), family_guid) FROM sys.database_recovery_status WHERE database_id = DB_ID()")
	if row.Err() != nil {
		return nil, row.Err()
	}
	err = row.Scan(&out)
	return
}

// decryptObject decrypts an object. requires a DAC connection to function as we access
// the sys.sysobjvalues table which is only available via a dedicated admin connection.
// Microsoft uses RC4 to encrypt objects. the RC4 key is derived from SHA1 hash of
// the Database Family GUID + the object id + sub object id and the decrypted source code
// is stored as UTF-16.
func decryptObject(db *sql.DB, guid []byte, id uint32) (string, error) {
	row := db.QueryRow("SELECT imageval, subobjid FROM sys.sysobjvalues WHERE objid = :1", id)
	if row.Err() != nil {
		return "", row.Err()
	}
	var (
		subobjid uint16
		imageval []byte
	)
	if err := row.Scan(&imageval, &subobjid); err != nil {
		return "", err
	}

	key := make([]byte, 16+4+2) // uuid + uint32 + uint16
	copy(key[:16], guid)
	binary.LittleEndian.PutUint32(key[16:20], id)
	binary.LittleEndian.PutUint16(key[20:22], subobjid)

	// hash the result to make the RC4 key
	rc4Key := sha1.Sum(key)

	decrypted := make([]byte, len(imageval))
	cipher, err := rc4.NewCipher(rc4Key[:])
	if err != nil {
		return "", err
	}
	cipher.XORKeyStream(decrypted, imageval)

	// convert the decrypted source code from UTF16 to UTF8
	parsed, err := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder().Bytes(decrypted)
	if err != nil {
		return "", err
	}

	return string(parsed), nil
}

// helper function to find if user provided a flag
func isFlagProvided(name string) bool {
	flagFound := false
	flag.Visit(func(flag *flag.Flag) {
		if flag.Name == name {
			flagFound = true
		}
	})
	return flagFound
}

func main() {
	var (
		dbHost            string
		dacPort           int
		databse           string
		username          string
		password          string
		disableEncryption bool
	)

	flag.StringVar(&dbHost, "host", "127.0.0.1", "database server address.")
	flag.IntVar(&dacPort, "dacport", 1434, "the DAC port. this is diffrent from the normal port.")
	flag.StringVar(&databse, "database", "master", "database name to connect to. must be the same as in the object id.")
	flag.StringVar(&username, "username", "sa", "username to use for the DAC connection.")
	flag.StringVar(&password, "password", "", "database password, the program will ask for password interactively if it's not provided.")
	flag.BoolVar(&disableEncryption, "disable-encryption", false, "completely disables encryption. use this to connect to sql server 2008.")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags] object\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(1)
	}

	if !isFlagProvided("password") {
		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			panic(err)
		}
		password = string(passwordBytes)
		fmt.Println()
	}

	query := url.Values{}
	query.Add("app name", "SQLDecryptor")
	query.Add("database", databse)
	if disableEncryption {
		query.Add("encrypt", "disable")
	}

	u := &url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(username, password),
		Host:     fmt.Sprintf("%s:%d", dbHost, dacPort),
		RawQuery: query.Encode(),
	}

	db, err := sql.Open("mssql", u.String())
	if err != nil {
		log.Fatalln(err)
	}
	defer db.Close()

	objectID, err := getObjectID(db, flag.Arg(0))
	if err != nil {
		log.Fatalln(err)
	}

	dbFamilyGUID, err := getDbFamilyGUID(db)
	if err != nil {
		log.Fatalln(err)
	}

	decrypted, err := decryptObject(db, dbFamilyGUID, objectID)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(decrypted)
}
