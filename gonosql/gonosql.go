package gonosql

import (
	"context"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"gopkg.in/mgo.v2/bson"
)

type Repository interface {
	InsertOne(ctx context.Context, storage *mongo.Collection, models interface{}) (*mongo.InsertOneResult, error)
	GetByKey(ctx context.Context, storage *mongo.Collection, key, value string) (*mongo.Cursor, error)
	GetByFilter(ctx context.Context, storage *mongo.Collection, filter bson.M) (*mongo.Cursor, error)
	Get(ctx context.Context, storage *mongo.Collection, id string) (*mongo.SingleResult, error)
	GetAll(ctx context.Context, storage *mongo.Collection) (*mongo.Cursor, error)
	GetByIDs(ctx context.Context, storage *mongo.Collection, ids []string) (*mongo.Cursor, error)
	Delete(ctx context.Context, storage *mongo.Collection, id string) (*mongo.DeleteResult, error)
	Update(ctx context.Context, storage *mongo.Collection, id string, updateDocument interface{}) (*mongo.UpdateResult, error)
	UpdateByFilter(ctx context.Context, storage *mongo.Collection, id string, filter bson.M) (*mongo.UpdateResult, error)
	Search(ctx context.Context, storage *mongo.Collection, keyword string) (*mongo.Cursor, error)
	CountDocuments(ctx context.Context, storage *mongo.Collection, id string) (int64, error)
	CountDocumentsByFilter(ctx context.Context, storage *mongo.Collection, filter bson.M) (int64, error)
}

func InsertOne(ctx context.Context, storage *mongo.Collection, models interface{}) (*mongo.InsertOneResult, error) {
	return storage.InsertOne(ctx, models)
}

func GetByKey(ctx context.Context, storage *mongo.Collection, key, value string) (*mongo.Cursor, error) {
	filter := bson.M{key: value}
	return storage.Find(ctx, filter)
}

func GetByFilter(ctx context.Context, storage *mongo.Collection, filter bson.M) (*mongo.Cursor, error) {
	return storage.Find(ctx, filter)
}

func Get(ctx context.Context, storage *mongo.Collection, id string) (*mongo.SingleResult, error) {
	// TODO add findOneOptions in method
	primitiveID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}
	return storage.FindOne(ctx, bson.M{"_id": primitiveID}), nil
}

func GetAll(ctx context.Context, storage *mongo.Collection) (*mongo.Cursor, error) {
	return storage.Find(ctx, bson.M{})
}

func GetByIDs(ctx context.Context, storage *mongo.Collection, ids []string) (*mongo.Cursor, error) {
	var objectIDs []primitive.ObjectID
	for _, id := range ids {
		objectID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			return nil, err
		}
		objectIDs = append(objectIDs, objectID)
	}
	return storage.Find(ctx, bson.M{"_id": bson.M{"$in": objectIDs}})
}

func Delete(ctx context.Context, storage *mongo.Collection, id string) (*mongo.DeleteResult, error) {
	primitiveID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}
	return storage.DeleteOne(ctx, bson.M{"_id": primitiveID})
}

func Update(ctx context.Context, storage *mongo.Collection, id string, updateDocument interface{}) (*mongo.UpdateResult, error) {
	primitiveID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}
	return storage.UpdateOne(ctx, bson.M{"_id": primitiveID}, bson.M{"$set": updateDocument})
}

func UpdateByFilter(ctx context.Context, storage *mongo.Collection, id string, filter bson.M) (*mongo.UpdateResult, error) {
	primitiveID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}
	return storage.UpdateOne(ctx, bson.M{"_id": primitiveID}, filter)
}

func Search(ctx context.Context, storage *mongo.Collection, keyword string) (*mongo.Cursor, error) {
	filter := bson.M{
		"$or": []bson.M{
			{"name": bson.M{"$regex": keyword}},
			{"description": bson.M{"$regex": keyword}},
		},
	}
	return GetByFilter(ctx, storage, filter)
}

func CountDocuments(ctx context.Context, storage *mongo.Collection, id string) (int64, error) {
	primitiveID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return 0, err
	}
	return CountDocumentsByFilter(ctx, storage, bson.M{"_id": primitiveID})
}

func CountDocumentsByFilter(ctx context.Context, storage *mongo.Collection, filter bson.M) (int64, error) {
	return storage.CountDocuments(ctx, filter)
}
