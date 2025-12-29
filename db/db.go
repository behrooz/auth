package db

import (
	"context"
	"log"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	Client         *mongo.Client
	UserCollection *mongo.Collection
)

func InitDB() {
	clientOptions := options.Client().ApplyURI("mongodb://root:pass@server:port/")
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	UserCollection = client.Database("vcluster").Collection("users")
}
