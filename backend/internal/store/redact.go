package store

import (
	"errors"
	"regexp"
)

// dsnPassword matches the password component of a postgres URL.
var dsnPassword = regexp.MustCompile(`(postgres(?:ql)?://[^:/@\s]+):[^@\s]*@`)

// redact removes credentials from an error before it is logged or returned.
// Driver errors routinely quote the connection string verbatim.
func redact(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(dsnPassword.ReplaceAllString(err.Error(), "$1:REDACTED@"))
}
