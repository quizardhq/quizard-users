package wailist

import (
	"github.com/quizardhq/internal/providers"
)

func NewWailist(email string) error {
	prefineryBaseUrl := "https://api.getwaitlist.com/api/v1/"

	data := map[string]string{"email": email, "waitlist_id": "5803"}

	p := provider.NewHttpProvider(prefineryBaseUrl)

	headers := map[string]string{}
	_, err := p.Post("/waiter", data, headers)

	if err != nil {
		return err
	}
	return nil
}
