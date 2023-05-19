package helpers

import (
	"github.com/asaskevich/govalidator"
)

func ValidateBody(body interface{}) error {
	govalidator.SetFieldsRequiredByDefault(true)

	_, err := govalidator.ValidateStruct(body)
	if err != nil {
		return err
	}

	return nil
}
