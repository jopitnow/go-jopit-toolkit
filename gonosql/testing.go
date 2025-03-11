package gonosql

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/tryvium-travels/memongo"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var server *memongo.Server

var (
	memongoData Data
	memongoOnce sync.Once
)

func OpenNoSQLMock(server *memongo.Server) *Data {
	memongoOnce.Do(func() {
		initNoSQLMock(server)
	})

	return &memongoData
}

func CloseNoSQLMock() {
	if &memongoData == nil {
		return
	}

	if err := memongoData.DB.Disconnect(context.Background()); err != nil {
		fmt.Println("Error disconnecting database.", err)
	}

	fmt.Println("Connection closed successfully.")
}

func initNoSQLMock(server *memongo.Server) {
	var (
		errDB    error
		database *mongo.Database
	)
	db, err := getConnection(server)
	if err != nil {
		errDB = fmt.Errorf("error NoSQL connection: %s", err)
	} else {
		// Check the connections
		if err = db.Ping(context.Background(), nil); err != nil {
			errDB = fmt.Errorf("error NoSQL connection: %s", err)
		}
		database = db.Database(memongo.RandomDatabase())
	}

	memongoData = Data{
		DB:       db,
		Error:    errDB,
		Database: database,
	}
}

func getConnection(server *memongo.Server) (*mongo.Client, error) {
	clientOptions := options.Client().ApplyURI(server.URI())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)

	defer cancel()

	return mongo.Connect(ctx, clientOptions)
}

func StartMemongo() (*memongo.Server, error) {
	return memongo.Start("6.0.19")
}

func AfterMemongoTestCase() {
	closeNoSQLMock()
	server.Stop()
}

func closeNoSQLMock() {
	if &memongoData == nil {
		return
	}

	if err := memongoData.DB.Disconnect(context.Background()); err != nil {
		fmt.Println("Error disconnecting database.", err)
	}

	fmt.Println("Connection closed successfully.")
}
