package handlers

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"main/crypto"

	"github.com/gofiber/fiber/v2"
	uuid "github.com/satori/go.uuid"
	"go.mongodb.org/mongo-driver/v2/bson" // Changed from non-versioned bson
	"go.mongodb.org/mongo-driver/v2/mongo"

	"main/api"
	"main/database"
	"main/types"
)

type Handlers struct {
	Instance *InstanceHandler
	Proxy    *ProxyHandler
}

func NewHandlers(collection *mongo.Collection) *Handlers {
	return &Handlers{
		Instance: NewInstanceHandler(collection),
		Proxy:    NewProxyHandler(collection),
	}
}

func RegisterInstance(collection *mongo.Collection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var requestBody types.PartialInstanceInfo
		if err := c.BodyParser(&requestBody); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err})
		}

		instance, err := database.FetchInstanceByInstanceName(*collection, requestBody.InstanceName)
		if instance != nil {
			return c.Status(400).JSON(fiber.Map{"error": "instance with provided name exists"})
		}
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err})
		}

		newInstance := createNewInstance(requestBody)
		privateKey, err := setupInstanceEncryption(&newInstance, requestBody.Token)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err})
		}

		database.CreateInstanceInfo(*collection, newInstance)

		return c.JSON(fiber.Map{
			"instance":   newInstance,
			"privateKey": privateKey,
		})
	}
}

func GetInstance(collection *mongo.Collection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		instance, err := database.GetInstanceInfo(*collection, bson.M{"instance_id": c.Params("instanceID")})
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err})
		}
		return c.JSON(instance)
	}
}

func FetchAllInstances(collection *mongo.Collection) fiber.Handler {
	return func(c *fiber.Ctx) error {
		results, err := collection.Find(context.TODO(), bson.M{})
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		var instances []*types.InstanceInfo
		if err = results.All(context.TODO(), &instances); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		}

		return c.JSON(fiber.Map{"instances": instances})
	}
}

func APIProxy(collection *mongo.Collection) fiber.Handler {
	proxyService := api.NewProxyService()
	return func(c *fiber.Ctx) error {
		path := c.Path()

		if strings.Contains(path, "get_mutual_guilds") || strings.Contains(path, "get_staff_guilds") {
			return handleMutualGuildsRequest(c, collection, proxyService, path)
		}

		return handleGuildRequest(c, collection, path)
	}
}

func createNewInstance(req types.PartialInstanceInfo) types.InstanceInfo {
	return types.InstanceInfo{
		InstanceId:     uuid.NewV4().String(),
		InstanceName:   req.InstanceName,
		InstanceType:   req.InstanceType,
		InstanceStatus: 0,
		Protocol:       req.Protocol,
		Hostname:       req.Hostname,
	}
}

func setupInstanceEncryption(instance *types.InstanceInfo, token string) (string, error) {
	privateKey, err := crypto.GenerateEncryptionMaterial(instance.InstanceId)
	if err != nil {
		return "", err
	}

	sha256_hash, encrypted_token, err := crypto.EncryptToken(&privateKey.PublicKey, token)
	if err != nil {
		return "", err
	}

	instance.SHA256Hash = sha256_hash.Sum(nil)
	instance.EncryptedToken = encrypted_token

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})), nil
}

func handleMutualGuildsRequest(c *fiber.Ctx, collection *mongo.Collection, proxyService *api.ProxyService, path string) error {
	var instances []types.InstanceInfo
	cursor, err := collection.Find(context.TODO(), bson.M{})
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	if err = cursor.All(context.TODO(), &instances); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	guilds, err := proxyService.GatherResponses(c, instances, path)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{"guilds": guilds})
}

func handleGuildRequest(c *fiber.Ctx, collection *mongo.Collection, path string) error {
	var guildObj types.GuildFetch
	if err := c.BodyParser(&guildObj); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err})
	}

	instance, err := database.FetchInstanceByGuild(*collection, guildObj.Guild)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err})
	}

	proxyService := api.NewProxyService()
	return proxyService.ForwardRequest(c, instance, path)
}
