package repository

import (
	"errors"
	"fmt"

	"github.com/quizardhq/internal/models"
	"gorm.io/gorm"
)

type UserRepository struct {
	database *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{
		database: db,
	}
}

func (a *UserRepository) FindUserByCondition(condition, value string) (*models.User, bool, error) {
	var user *models.User
	err := a.database.Raw(fmt.Sprintf(`SELECT * FROM users WHERE %s = ?`, condition), value).Scan(&user).Error
	if err != nil {
		return nil, false, err
	}
	if user != nil {
		return user, true, nil
	}
	return nil, false, nil
}

func (a *UserRepository) CreateUser(user *models.User) error {
	return a.database.Model(&models.User{}).Create(user).Error
}

func (a *UserRepository) UpdateUserByCondition(condition, value string, update *models.User) (*models.User, error) {
	user := &models.User{}
	rows := a.database.Model(user).Where(fmt.Sprintf(`%s = ?`, condition), value).Updates(&update).First(user)
	if rows.RowsAffected == 0 {
		return nil, errors.New("no record updated")
	}
	return user, nil
}
