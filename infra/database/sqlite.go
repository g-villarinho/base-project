package database

import (
	"fmt"

	"github.com/g-villarinho/base-project/config"
	"github.com/g-villarinho/base-project/internal/domain"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func NewSqliteDbConnection(config *config.Config) (*gorm.DB, error) {
	var gormConfig = &gorm.Config{}
	gormConfig.Logger = logger.Default.LogMode(logger.Silent)
	if config.ShowSQLLogs {
		gormConfig.Logger = logger.Default.LogMode(logger.Info)
	}

	db, err := gorm.Open(sqlite.Open(config.SqlLite.DatabaseName), gormConfig)
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get sql connection: %w", err)
	}

	sqlDB.SetMaxIdleConns(config.SqlLite.MaxIdle)
	sqlDB.SetMaxOpenConns(config.SqlLite.MaxConn)
	sqlDB.SetConnMaxLifetime(config.SqlLite.MaxLifeTime)

	if err := db.AutoMigrate(&domain.User{}, &domain.Verification{}, &domain.Session{}); err != nil {
		return nil, fmt.Errorf("migrate tables: %w", err)
	}

	return db, nil
}
