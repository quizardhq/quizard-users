package repository

import (
	"fmt"

	"github.com/quizardhq/internal/models"
	"gorm.io/gorm"
)

type WaitlistRepository struct {
	database *gorm.DB
}

func NewWaitlistRepository(db *gorm.DB) *WaitlistRepository {
	return &WaitlistRepository{
		database: db,
	}
}

func (w *WaitlistRepository) FindRecordByCondition(condition, value string) (*models.Waitlist, bool, error) {
	var record *models.Waitlist
	err := w.database.Raw(fmt.Sprintf(`SELECT * FROM waitlist WHERE %s = ?`, condition), value).Scan(&record).Error
	if err != nil {
		return nil, false, err
	}
	if record != nil {
		return record, true, nil
	}
	return nil, false, nil
}

func (w *WaitlistRepository) CreateRecord(record *models.Waitlist) error {
	return w.database.Table("waitlist").Create(record).Error
}
