package validate

import (
	"fmt"
	"regexp"
)

type argError struct {
	arg        string
	errMessage string
}

func (e *argError) Error() string {
	return fmt.Sprintf("%s", e.errMessage)
}

func Validate(arg string) error {

	regexEmail := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

	if len(arg) > 250 {
		return &argError{arg, "Email must be less than 250 characters."}
	}

	if !regexEmail.MatchString(arg) {
		return &argError{arg, "Not a valid email address, please try again."}
	}

	return nil
}
