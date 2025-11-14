package gonosql

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jopitnow/go-jopit-toolkit/goutils/logger"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	mongoURI = "mongodb+srv://%s:%s@%s/?retryWrites=true&w=majority"
)

var (
	data *Data
	once sync.Once
)

type Data struct {
	DB       *mongo.Client
	Database *mongo.Database
	Error    error
}

type Config struct {
	Username string
	Password string
	Host     string
	Database string
}

// Close closes the resources used by data.
func (d *Data) Close() {
	if data == nil {
		return
	}

	if err := data.DB.Disconnect(context.Background()); err != nil {
		logger.Errorf("Error disconect DB", err)
	}
	logger.Debugf("Connection close sucessfully")
}

func (d *Data) NewCollection(collection string) *mongo.Collection {
	return d.Database.Collection(collection)
}

func NewNoSQL(mongoDbConnString string) *Data {
	once.Do(func() {
		InitNoSQL(mongoDbConnString)
	})

	return data
}

func parseMongoURI(uri string) (username, password, host string, err error) {
	// Remove the mongodb+srv:// prefix
	trimmed := strings.TrimPrefix(uri, "mongodb+srv://")

	// Split at the first slash to separate credentials/host from db
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("invalid URI format")
	}

	// Extract credentials and host
	hostPart := parts[0]
	atIndex := strings.LastIndex(hostPart, "@")
	if atIndex == -1 {
		return "", "", "", fmt.Errorf("missing '@' in URI")
	}

	creds := hostPart[:atIndex]
	host = hostPart[atIndex+1:]

	// Extract username and password
	colonIndex := strings.Index(creds, ":")
	if colonIndex == -1 {
		username = creds
	} else {
		username = creds[:colonIndex]
		password = creds[colonIndex+1:]
	}

	// Decode in case of URL encoding
	if decoded, err := url.QueryUnescape(username); err == nil {
		username = decoded
	}
	if decoded, err := url.QueryUnescape(password); err == nil {
		password = decoded
	}

	return username, password, host, nil
}

func GetConnection(host, username, password string) (*mongo.Client, error) {

	serverAPIOptions := options.ServerAPI(options.ServerAPIVersion1)
	clientOpts := options.Client().
		ApplyURI(fmt.Sprintf(mongoURI, username, password, host)).
		SetServerAPIOptions(serverAPIOptions)
	// TODO pass context? (Analyze)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return mongo.Connect(ctx, clientOpts)
}

func InitNoSQL(mongoDbConnString string) {
	var (
		errDB    error
		database *mongo.Database
	)

	username, password, host, err := parseMongoURI(mongoDbConnString)
	if err != nil {
		log.Fatalf("Error decoding the MongoDB Conn String: %s", err.Error())
	}

	db, err := GetConnection(host, username, password)
	if err != nil {
		errDB = fmt.Errorf("Error NoSQL connection: %s", err)
	} else {
		// Check the connections
		if err = db.Ping(context.TODO(), nil); err != nil {
			errDB = fmt.Errorf("Error NoSQL connection: %s", err)
		}
		database = db.Database("jopit")
	}

	data = &Data{
		DB:       db,
		Error:    errDB,
		Database: database,
	}
}
