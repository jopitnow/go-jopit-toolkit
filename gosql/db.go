package gosql

import (
	"fmt"
	"sync"

	"github.com/jinzhu/gorm"
	"gorm.io/gorm/clause"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

var (
	data *Data
	once sync.Once
)

const defaultPreload = clause.Associations

type Data struct {
	DB    *gorm.DB
	Error error
}

type JopitDBConfig struct {
	Username string
	Password string
	Host     string
	Port     string
	Database string
}

// Close closes the resources used by data.
func (d *Data) Close() error {
	if data == nil {
		return nil
	}

	return data.DB.Close()
}

func NewSQL(jopitDBConfig JopitDBConfig) *Data {
	once.Do(func() {
		InitSQL(jopitDBConfig)
	})

	return data
}

func GetConnection(jopitDBConfig JopitDBConfig) (*gorm.DB, error) {
	username := jopitDBConfig.Username
	password := jopitDBConfig.Password
	host := jopitDBConfig.Host
	port := jopitDBConfig.Port
	database := jopitDBConfig.Database
	connection := username + ":" + password + "@" + "tcp(" + host + ":" + port + ")/" + database + "?charset=utf8&parseTime=true"
	return gorm.Open("mysql", connection)
}

func InitSQL(jopitDBConfig JopitDBConfig) {
	var errDB error
	db, err := GetConnection(jopitDBConfig)
	if err != nil {
		errDB = fmt.Errorf("Error MySQL connection: %s", err)
	}
	data = &Data{
		DB:    db,
		Error: errDB,
	}
}
