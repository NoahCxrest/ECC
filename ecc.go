package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/bytedance/sonic"
	"github.com/caarlos0/env/v11"
	"github.com/charmbracelet/log" // this is just to make things pretty
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	uuid "github.com/satori/go.uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"hash"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
)

var instanceCollection *mongo.Collection

type eccConfig struct {
	MongoURL     string `env:"MONGO_URL"`
	DatabaseName string `env:"MONGO_DB_NAME"`
}

type InstanceInfo struct {
	InstanceId     string   `bson:"instance_id"`
	InstanceName   string   `bson:"instance_name"`
	InstanceType   string   `bson:"instance_type"`
	InstanceStatus int      `bson:"instance_status"`
	EncryptedToken []byte   `bson:"encrypted_token"`
	SHA256Hash     []byte   `bson:"sha256_hash"`
	ShardIds       []int    `bson:"shard_ids"`
	GuildIds       []string `bson:"guild_ids"`
	Hostname       string   `bson:"hostname"`
	Protocol       string   `bson:"protocol"`
}

type GuildFetch struct {
	Guild string `json:"guild"`
}

type GetMutualGuilds struct {
	Guilds []MutualGuild `json:"guilds"`
}

type MutualGuild struct {
	Name            string `json:"name"`
	ID              string `json:"id"`
	Icon            string `json:"icon_url"`
	MemberCount     string `json:"member_count"`
	PermissionLevel int    `json:"permission_level"`
}

type PartialInstanceInfo struct {
	InstanceName string
	InstanceType string
	Token        string
	Hostname     string
	Protocol     string
}

func UnmarshalHandler(data []byte) (interface{}, error) {
	var getMutualGuilds GetMutualGuilds
	err := sonic.Unmarshal(data, &getMutualGuilds)

	if err == nil && len(getMutualGuilds.Guilds) > 0 {
		return getMutualGuilds, nil
	}

	var mutualGuilds []MutualGuild
	err = sonic.Unmarshal(data, &mutualGuilds)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal data into supported types: %v", err)
	}

	return mutualGuilds, nil
}

func initClient(mongoURL string) (*mongo.Client, error) {
	client, err := mongo.Connect(options.Client().ApplyURI(mongoURL))
	if err != nil {
		return nil, err
	} else {
		return client, nil
	}
}

func loadEnvironment() *eccConfig {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	var ecc eccConfig
	if err := env.Parse(&ecc); err != nil {
		log.Fatal(err)
		return nil
	}
	return &ecc
}

func getInstanceInfo(collection mongo.Collection, uniqueId string) (*InstanceInfo, error) {
	result := collection.FindOne(context.TODO(), bson.D{{"instance_id", uniqueId}})
	if result == nil {
		return nil, errors.New("instance not found")
	}
	var instance InstanceInfo
	if err := result.Decode(&instance); err != nil {
		return nil, err
	}
	return &instance, nil
}

func createInstanceInfo(collection mongo.Collection, info InstanceInfo) {
	_, err := collection.InsertOne(context.TODO(), info)
	if err != nil {
		log.Fatal(err)
	}
}

func assignShardIdentifiers(collection mongo.Collection, instanceType string, totalShardCount int) (map[string][]int, error) {
	documentCursor, _ := collection.Find(context.TODO(), bson.D{{"instance_type", instanceType}, {"instance_status", 0}})

	var floatedShardCount float32 = float32(totalShardCount)

	var results []InstanceInfo
	if err := documentCursor.All(context.TODO(), &results); err != nil {
		return nil, err
	}

	var shardsPerDocument int = int(math.Ceil(float64(floatedShardCount / float32(len(results)))))
	var documents map[string][]int = map[string][]int{}

	for shard, document := 0, 0; float32(shard) <= floatedShardCount && document < len(results); document, shard = document+1, shard+shardsPerDocument {
		shardsToCompleteTo := shard + shardsPerDocument - 1

		var info InstanceInfo = results[document]

		var shardSlice []int
		for i := shard; i <= shardsToCompleteTo && i <= totalShardCount; i++ {
			shardSlice = append(shardSlice, i)
		}

		info.ShardIds = shardSlice
		documents[info.InstanceId] = shardSlice
	}
	return documents, nil
}

func deleteAllInstances(collection mongo.Collection) error {
	_, err := collection.DeleteMany(context.TODO(), bson.D{})
	if err != nil {
		return err
	}
	return nil
}

func fetchInstanceByInstanceName(collection mongo.Collection, instanceName string) (*InstanceInfo, error) {
	result := collection.FindOne(context.TODO(), bson.D{{"instance_name", instanceName}})
	if result == nil {
		return nil, nil
	}

	var instance InstanceInfo

	if err := result.Decode(&instance); err != nil {
		return nil, nil
	}
	return &instance, nil
}

func fetchInstanceByGuild(collection mongo.Collection, guildID string) (*InstanceInfo, error) {
	result := collection.FindOne(context.TODO(), bson.D{{"guild_ids", guildID}})
	if result == nil {
		return nil, nil
	}

	var instance InstanceInfo

	if err := result.Decode(&instance); err != nil {
		return nil, nil
	}
	return &instance, nil
}

func fetchInstanceByShard(collection mongo.Collection, shardID int) (*InstanceInfo, error) {
	result := collection.FindOne(context.TODO(), bson.D{{"shard_ids", shardID}})
	if result == nil {
		return nil, nil
	}

	var instance InstanceInfo

	if err := result.Decode(&instance); err != nil {
		return nil, nil
	}
	return &instance, nil
}

func fetchAllInstances(fiberContext *fiber.Ctx) error {
	results, err := instanceCollection.Find(context.TODO(), bson.D{})
	if err != nil {
		err := fiberContext.JSON(fiber.Map{"error": err})
		if err != nil {
			return err
		}
		return fiberContext.SendStatus(500)
	}

	var decodedResults []*InstanceInfo

	err = results.All(context.TODO(), &decodedResults)

	if err != nil {
		log.Fatal(err)
	}

	return fiberContext.JSON(fiber.Map{"instances": decodedResults})
}

func generateEncryptionMaterial(instanceId string) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	publicKey := &privateKey.PublicKey

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	})
	err = os.WriteFile(fmt.Sprintf("keys/%s.pem", instanceId), pubKeyPEM, 0600)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func encryptToken(rsaPublicKey *rsa.PublicKey, token string) (hash.Hash, []byte, error) {
	sha256_hash := sha256.New()
	encrypted, err := rsa.EncryptOAEP(sha256_hash, rand.Reader, rsaPublicKey, []byte(token), nil)
	if err != nil {
		return nil, nil, err
	}
	return sha256_hash, encrypted, err
}

func registerInstance(fiberContext *fiber.Ctx) error {
	var requestBody PartialInstanceInfo

	if err := fiberContext.BodyParser(&requestBody); err != nil {
		err := fiberContext.JSON(fiber.Map{"error": err})
		if err != nil {
			return err
		}
		return fiberContext.SendStatus(500)
	}

	instance, err := fetchInstanceByInstanceName(*instanceCollection, requestBody.InstanceName)
	if instance != nil {
		fiberContext.JSON(fiber.Map{"error": "instance with provided name exists"})
		return fiberContext.SendStatus(400)
	}
	if err != nil {
		fiberContext.JSON(fiber.Map{"error": err})
		return fiberContext.SendStatus(500)
	}

	var newInstance InstanceInfo

	newInstance.InstanceId = uuid.NewV4().String()
	newInstance.InstanceName = requestBody.InstanceName
	newInstance.InstanceType = requestBody.InstanceType
	newInstance.Protocol = requestBody.Protocol
	newInstance.Hostname = requestBody.Hostname

	// encryption
	privateKey, err := generateEncryptionMaterial(newInstance.InstanceId)
	if err != nil || privateKey == nil {
		err := fiberContext.JSON(fiber.Map{"error": err})
		if err != nil {
			return err
		}
		return fiberContext.SendStatus(500)
	}

	sha256_hash, encrypted_token, err := encryptToken(privateKey.Public().(*rsa.PublicKey), requestBody.Token)
	if err != nil {
		err := fiberContext.JSON(fiber.Map{"error": err})
		if err != nil {
			return err
		}
		return fiberContext.SendStatus(500)
	}
	newInstance.SHA256Hash = sha256_hash.Sum(nil)
	newInstance.EncryptedToken = encrypted_token

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	privateKeyString := string(privateKeyPEM)

	createInstanceInfo(*instanceCollection, newInstance)

	return fiberContext.JSON(
		fiber.Map{
			"instance":   newInstance,
			"privateKey": privateKeyString,
		},
	)
}

func getInstance(fiberContext *fiber.Ctx) error {
	instance, err := getInstanceInfo(*instanceCollection, fiberContext.Params("instanceID"))
	if err != nil {
		fiberContext.JSON(fiber.Map{"error": err})
		return fiberContext.SendStatus(500)
	}

	return fiberContext.JSON(instance)
}

func shardCalculator(guild_id int64, total_shard_count int) int {
	return (int(guild_id) >> 22) % total_shard_count
}

func sendRequestToTargets(c *fiber.Ctx, targets []string) ([]interface{}, error) {
	var bodies []interface{}

	for _, target := range targets {

		request, _ := http.NewRequest(c.Method(), target, bytes.NewBuffer(c.Body()))
		origHeaders := c.GetReqHeaders()
		// set request headers to be orig_headers

		for key, values := range origHeaders {
			for _, value := range values {
				request.Header.Add(key, value)
			}
		}

		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			return nil, c.Status(http.StatusInternalServerError).SendString(err.Error())
		}

		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, c.Status(http.StatusInternalServerError).SendString(err.Error())
		}

		newData, err := UnmarshalHandler(body)
		log.Info("sendRequestToTargets", "body", body, "err", err)
		if err != nil {
			log.Fatal(err)
		}
		bodies = append(bodies, newData)
	}
	return bodies, nil
}

func main() {

	log.Info("Starting database connection ...")

	// loading the environment
	var environment *eccConfig = loadEnvironment()
	log.Info("Loaded environment ...")

	client, err := initClient(environment.MongoURL)
	if err != nil {
		log.Fatal(err)
	}

	database := client.Database(environment.DatabaseName)
	collection := database.Collection("Instances")
	instanceCollection = collection

	// THIS IS FOR TESTING ONLY.
	err = deleteAllInstances(*collection)
	if err != nil {
		log.Fatal(err)
	}

	for i := 1; i < 5; i += 1 {
		// fabricate test data so we can test the automatic shard id allocation system
		createInstanceInfo(*collection, InstanceInfo{
			InstanceId:     uuid.NewV4().String(),
			InstanceName:   fmt.Sprintf("instance-%d", i),
			InstanceType:   "PRODUCTION",
			InstanceStatus: 0,
			EncryptedToken: make([]byte, 1),
			SHA256Hash:     make([]byte, 1),
			ShardIds:       []int{},
			Protocol:       "HTTPS",
			Hostname:       os.Getenv("PRODUCTION_TEST_HOSTNAME"),
		})
		log.Info("Created instance ", "id", i)
	}

	ids_to_shards, err := assignShardIdentifiers(*collection, "PRODUCTION", 22)
	for instanceId, shard := range ids_to_shards {
		_, err2 := collection.UpdateOne(context.TODO(), bson.D{{"instance_id", instanceId}}, bson.D{{"$set", bson.D{{"shard_ids", shard}}}})
		if err2 != nil {
			log.Fatal(err2)
		}
		log.Warn(fmt.Sprintf("Assigning shards %s to instance: %s", fmt.Sprint(shard), instanceId))
	}

	// Startup the HTTP server...

	app := fiber.New()

	app.Get("/", func(fiberContext *fiber.Ctx) error {
		return fiberContext.JSON(fiber.Map{
			"message": "OK",
		})
	})

	app.Get("/instance/:instanceID", getInstance)
	app.Get("/all", fetchAllInstances)
	app.Post("/create", registerInstance)

	app.Use("/api/*", func(c *fiber.Ctx) error {
		path := c.Path()

		if strings.Contains(path, "get_mutual_guilds") || strings.Contains(path, "get_staff_guilds") {
			// needs to hit all nodes, unfortunately.
			results, err := instanceCollection.Find(context.TODO(), bson.D{})

			if err != nil {
				log.Error(err)
			}

			var resultArray []InstanceInfo

			err = results.All(context.TODO(), &resultArray)
			if err != nil {
				return err
			}

			var targets []string = make([]string, 0, len(resultArray))

			for _, result := range resultArray {
				targets = append(targets, fmt.Sprintf("%s://%s%s", strings.ToLower(result.Protocol), result.Hostname, strings.Replace(path, "api/", "", 1)))
			}

			// make a request for every hostname

			var bodies []interface{}

			bodies, err = sendRequestToTargets(c, targets)
			log.Warn(bodies)

			if err != nil {
				c.JSON(fiber.Map{"err": err})
				return c.SendStatus(500)
			}

			var combined_body []MutualGuild

			for _, body := range bodies {
				t, ok := body.(GetMutualGuilds)
				if !ok {
					t, _ := body.([]MutualGuild)
					log.Warn(t)
					for _, guild := range t {
						if !slices.Contains(combined_body, guild) {
							combined_body = append(combined_body, guild)
						}
					}
				} else {
					for _, guild := range t.Guilds {
						if !slices.Contains(combined_body, guild) {
							combined_body = append(combined_body, guild)
						}
					}
				}
			}

			var returnValue fiber.Map

			if strings.Contains(path, "get_mutual_guilds") {
				returnValue = fiber.Map{
					"guilds": combined_body,
				}
			} else {
				return c.JSON(combined_body)
			}

			return c.JSON(returnValue)
		}

		var guildObj GuildFetch

		err := c.BodyParser(&guildObj)
		if err != nil {
			c.JSON(fiber.Map{
				"error": err,
			})
			return c.SendStatus(500)
		}

		log.Info(guildObj.Guild)
		if guildObj.Guild == "" {
			c.JSON(fiber.Map{
				"error": err,
			})
			return c.SendStatus(500)
		}

		instance, err := fetchInstanceByGuild(*instanceCollection, guildObj.Guild)
		if instance == nil {
			guildId, err := strconv.ParseInt(guildObj.Guild, 10, 64)
			if err != nil {
				c.JSON(fiber.Map{
					"error": err,
				})
				return c.SendStatus(500)
			}
			shard := shardCalculator(guildId, 22)
			log.Warn("shard", "id", shard)
			instance, err = fetchInstanceByShard(*instanceCollection, shard)
			log.Warn("instance", "instance", instance, "err", err)
			if err != nil {
				log.Fatal(err)
			}
		}

		if instance == nil {
			c.JSON(fiber.Map{"err": "no guild or shard found"})
			return c.SendStatus(500)
		}

		targetURL := fmt.Sprintf("%s://%s%s", strings.ToLower(instance.Protocol), instance.Hostname, strings.Replace(path, "api/", "", 1))
		log.Warn(targetURL)

		request, _ := http.NewRequest(c.Method(), targetURL, bytes.NewBuffer(c.Body()))
		origHeaders := c.GetReqHeaders()
		// set request headers to be orig_headers

		for key, values := range origHeaders {
			for _, value := range values {
				request.Header.Add(key, value)
			}
		}

		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			return c.Status(http.StatusInternalServerError).SendString(err.Error())
		}

		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return c.Status(http.StatusInternalServerError).SendString(err.Error())
		}

		c.Set("Content-Type", resp.Header.Get("Content-Type"))
		return c.Send(body)
	})

	listening_host := os.Getenv("LISTEN_HOST")
	listening_port := os.Getenv("LISTEN_PORT")

	if listening_host == "" || listening_port == "" {
		listening_host = "0.0.0.0"
		listening_port = "22516"
	}

	err = app.Listen(listening_host + ":" + listening_port)
	if err != nil {
		log.Fatal(err)
	}

	if err != nil {
		log.Fatal(err)
	}
}
