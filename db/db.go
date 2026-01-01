package db

import (
	"context"
	"log"
	"os"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	Client         *mongo.Client
	UserCollection *mongo.Collection
)

func InitDB() {
<<<<<<< HEAD
	// Get MongoDB connection string from environment variable
	connectionString := os.Getenv("MONGODB_CONNECTION_STRING")
	if connectionString == "" {
		connectionString = "mongodb://root:secret123@212.64.215.155:32169/"
		log.Println("Warning: MONGODB_CONNECTION_STRING not set, using default")
	}

	// Get database name from environment variable
	databaseName := os.Getenv("MONGODB_DATABASE")
	if databaseName == "" {
		databaseName = "vcluster"
	}

	// Get collection name from environment variable
	collectionName := os.Getenv("MONGODB_COLLECTION")
	if collectionName == "" {
		collectionName = "users"
	}

	clientOptions := options.Client().ApplyURI(connectionString)
=======
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://root:pass@server:port/"
	}
	clientOptions := options.Client().ApplyURI(mongoURI)
>>>>>>> 72991b1e5511707844f76cd4996eb74a49a1dc2b
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	UserCollection = client.Database(databaseName).Collection(collectionName)
}
