package yandexcloudmap

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/dgrijalva/jwt-go"
	compute "github.com/yandex-cloud/go-genproto/yandex/cloud/compute/v1"
	clickhouse "github.com/yandex-cloud/go-genproto/yandex/cloud/mdb/clickhouse/v1"
	mongodb "github.com/yandex-cloud/go-genproto/yandex/cloud/mdb/mongodb/v1"
	mysql "github.com/yandex-cloud/go-genproto/yandex/cloud/mdb/mysql/v1"
	postgresql "github.com/yandex-cloud/go-genproto/yandex/cloud/mdb/postgresql/v1"
	redis "github.com/yandex-cloud/go-genproto/yandex/cloud/mdb/redis/v1"
	resourcemanager "github.com/yandex-cloud/go-genproto/yandex/cloud/resourcemanager/v1"
	yandexcloudsdk "github.com/yandex-cloud/go-sdk"
)

// Authentication Related Variables and Functions

// YandexAuthKey - Authorized key format for yandex cloud
type YandexAuthKey struct {
	ID               string `json:"id"`
	ServiceAccountID string `json:"service_account_id"`
	CreatedAt        string `json:"created_at"`
	KeyAlgorithm     string `json:"key_algorithm"`
	PublicKey        string `json:"public_key"`
	PrivateKey       string `json:"private_key"`
}

var ps256WithSaltLengthEqualsHash = &jwt.SigningMethodRSAPSS{
	SigningMethodRSA: jwt.SigningMethodPS256.SigningMethodRSA,
	Options: &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	},
}

// YandexCTX - API Context, is Background() on SDK init
var YandexCTX context.Context

// InitYandexSDK - returns Yandex API SDK, provided KeyFile is json formatted authorized key filename
func InitYandexSDK(keyFile []byte) (*yandexcloudsdk.SDK, error) {
	keyData := YandexAuthKey{}
	err := json.Unmarshal([]byte(keyFile), &keyData)
	if err != nil {
		return nil, err
	}
	rsaPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(keyData.PrivateKey))
	issuedAt := time.Now()
	yandexToken := jwt.NewWithClaims(ps256WithSaltLengthEqualsHash, jwt.StandardClaims{
		Issuer:    keyData.ServiceAccountID,
		IssuedAt:  issuedAt.Unix(),
		ExpiresAt: issuedAt.Add(time.Hour).Unix(),
		Audience:  "https://iam.api.cloud.yandex.net/iam/v1/tokens",
	})
	yandexToken.Header["kid"] = keyData.ID
	tokenSigned, err := yandexToken.SignedString(rsaPrivateKey)
	if err != nil {
		return nil, err
	}
	yandexResp, err := http.Post(
		"https://iam.api.cloud.yandex.net/iam/v1/tokens",
		"application/json",
		strings.NewReader(fmt.Sprintf(`{"jwt":"%s"}`, tokenSigned)),
	)
	if err != nil {
		return nil, err
	}
	defer yandexResp.Body.Close()
	if yandexResp.StatusCode != http.StatusOK {
		// Would be nice not to panic
		body, _ := ioutil.ReadAll(yandexResp.Body)
		// would be really nice not to panic
		log.Panic(fmt.Sprintf("%s: %s", yandexResp.Status, body))
	}
	var yandexIAMToken struct {
		IAMToken string `json:"iamToken"`
	}
	err = json.NewDecoder(yandexResp.Body).Decode(&yandexIAMToken)
	if err != nil {
		return nil, err
	}
	YandexCTX := context.Background()
	yandexSDK, err := yandexcloudsdk.Build(YandexCTX, yandexcloudsdk.Config{
		Credentials: yandexcloudsdk.NewIAMTokenCredentials(yandexIAMToken.IAMToken),
	})
	if err != nil {
		return nil, err
	}
	return yandexSDK, nil
}

const (
	yandexMaxPaginator = 1000
)

// YandexCloudSpaceView structure
//type YandexCloudSpaceView struct {
//	Cloud interface{} `json:"cloud"`
//}

// YandexCloud - Something that has everything
//var YandexCloud YandexCloudSpaceView

// YandexCloudStruct - describes a cloud information
type YandexCloudStruct struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
}

// YandexFolderStruct - describes some folder information
type YandexFolderStruct struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	CreatedAt       string `json:"created_at"`
	ParentCloudName string `json:"parent_cloud_name"`
	ParentCloudID   string `json:"parent_cloud_id"`
}

// YandexInstanceStruct - describes some folder information
type YandexInstanceStruct struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	CreatedAt        string            `json:"created_at"`
	ZoneID           string            `json:"zone_id"`
	Labels           interface{}       `json:"labels"`
	Metadata         map[string]string `json:"metadata"`
	ParentFolderName string            `json:"parent_cloud_name"`
	ParentFolderID   string            `json:"parent_cloud_id"`
}

// YandexMySQLStruct - describes some MDB.MySQL information
type YandexMySQLStruct struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	Description      string      `json:"description"`
	CreatedAt        string      `json:"created_at"`
	Labels           interface{} `json:"labels"`
	ParentFolderName string      `json:"parent_folder_name"`
	ParentFolderID   string      `json:"parent_folder_id"`
}

// YandexMongoDBStruct - describes some MDB.MongoDB information
type YandexMongoDBStruct struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	Description      string      `json:"description"`
	CreatedAt        string      `json:"created_at"`
	Labels           interface{} `json:"labels"`
	ParentFolderName string      `json:"parent_folder_name"`
	ParentFolderID   string      `json:"parent_folder_id"`
}

// YandexPostgreSQLStruct - describes some MDB.PostgresDB information
type YandexPostgreSQLStruct struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	Description      string      `json:"description"`
	CreatedAt        string      `json:"created_at"`
	Labels           interface{} `json:"labels"`
	ParentFolderName string      `json:"parent_folder_name"`
	ParentFolderID   string      `json:"parent_folder_id"`
}

// YandexRedisStruct - describes some MDB.Redis information
type YandexRedisStruct struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	Description      string      `json:"description"`
	CreatedAt        string      `json:"created_at"`
	Labels           interface{} `json:"labels"`
	ParentFolderName string      `json:"parent_folder_name"`
	ParentFolderID   string      `json:"parent_folder_id"`
}

// YandexClickHouseStruct - describes some MDB.ClickHouse information
type YandexClickHouseStruct struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	Description      string      `json:"description"`
	CreatedAt        string      `json:"created_at"`
	Labels           interface{} `json:"labels"`
	ParentFolderName string      `json:"parent_folder_name"`
	ParentFolderID   string      `json:"parent_folder_id"`
}

// YandexDiskStruct - describes some Compute.Disk information
type YandexDiskStruct struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	Description      string      `json:"description"`
	CreatedAt        string      `json:"created_at"`
	Labels           interface{} `json:"labels"`
	ParentFolderName string      `json:"parent_folder_name"`
	ParentFolderID   string      `json:"parent_folder_id"`
}

// YandexStorageStruct - describes some Compute.Disk information
type YandexStorageStruct struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	Description      string      `json:"description"`
	CreatedAt        string      `json:"created_at"`
	Labels           interface{} `json:"labels"`
	ParentFolderName string      `json:"parent_folder_name"`
	ParentFolderID   string      `json:"parent_folder_id"`
}

// YandexClouds - Surface Map for yandex cloud
type YandexClouds struct {
	Clouds        []*YandexCloudStruct      `json:"clouds"`
	Folders       []*YandexFolderStruct     `json:"folers"`
	Instances     []*YandexInstanceStruct   `json:"instances"`
	Disks         []*YandexDiskStruct       `json:"disks"`
	MDBMySQL      []*YandexMySQLStruct      `json:"mysql"`
	MDBMongoDB    []*YandexMongoDBStruct    `json:"mongodb"`
	MDBPostgreSQL []*YandexPostgreSQLStruct `json:"posgresql"`
	MBDRedis      []*YandexRedisStruct      `json:"redis"`
	MDBClickHouse []*YandexClickHouseStruct `json:"clickhouse"`
}

// YandexCloud - Structure with all info
var YandexCloud YandexClouds

func appendClouds(Clouds []*YandexCloudStruct, yandexClouds []*resourcemanager.Cloud) []*YandexCloudStruct {
	for _, cloud := range yandexClouds {
		Clouds = append(Clouds, &YandexCloudStruct{
			ID:          cloud.Id,
			Name:        cloud.Name,
			Description: cloud.Description,
			CreatedAt:   cloud.CreatedAt.String(),
		})
	}
	return Clouds
}

// GetYandexClouds - Returns Yandex Clouds slice
func GetYandexClouds(ctx context.Context, sdk *yandexcloudsdk.SDK) ([]*YandexCloudStruct, error) {
	theClouds := make([]*YandexCloudStruct, 0)
	// Would be nice to paginate
	clouds, err := sdk.ResourceManager().Cloud().List(ctx, &resourcemanager.ListCloudsRequest{
		PageSize: yandexMaxPaginator,
	})
	if err != nil {
		return nil, err
	}
	theClouds = appendClouds(theClouds, clouds.Clouds)
	for clouds.NextPageToken != "" {
		clouds, err = sdk.ResourceManager().Cloud().List(ctx, &resourcemanager.ListCloudsRequest{
			PageSize:  yandexMaxPaginator,
			PageToken: clouds.NextPageToken,
		})
		if err != nil {
			return nil, err
		}
		theClouds = appendClouds(theClouds, clouds.Clouds)
	}
	return theClouds, err
}

// appendFolders - aux slice append
func appendFolders(Folders []*YandexFolderStruct, cloud *YandexCloudStruct, yandexFolders []*resourcemanager.Folder) []*YandexFolderStruct {
	for _, folder := range yandexFolders {
		Folders = append(Folders, &YandexFolderStruct{
			ID:              folder.Id,
			Name:            folder.Name,
			Description:     folder.Description,
			CreatedAt:       folder.CreatedAt.String(),
			ParentCloudID:   cloud.ID,
			ParentCloudName: cloud.Name,
		})
	}
	return Folders
}

// GetYandexFolders - gets folders info for all provided clouds
func GetYandexFolders(ctx context.Context, sdk *yandexcloudsdk.SDK, clouds []*YandexCloudStruct) ([]*YandexFolderStruct, error) {
	theFolders := make([]*YandexFolderStruct, 0)
	for _, cloud := range clouds {
		folders, err := sdk.ResourceManager().Folder().List(ctx, &resourcemanager.ListFoldersRequest{
			CloudId:  cloud.ID,
			PageSize: yandexMaxPaginator,
		})
		if err != nil {
			return nil, err
		}
		theFolders = appendFolders(theFolders, cloud, folders.Folders)
		for folders.NextPageToken != "" {
			folders, err = sdk.ResourceManager().Folder().List(ctx, &resourcemanager.ListFoldersRequest{
				CloudId:   cloud.ID,
				PageSize:  yandexMaxPaginator,
				PageToken: folders.NextPageToken,
			})
			if err != nil {
				return nil, err
			}
			theFolders = appendFolders(theFolders, cloud, folders.Folders)
		}
	}
	return theFolders, nil
}

func convertMapToSlice(theMap map[string]string) [][]string {
	pairs := [][]string{}
	for key, value := range theMap {
		pairs = append(pairs, []string{key, value})
	}
	return pairs
}

// aux slice append
func appendInstances(Instances []*YandexInstanceStruct, folder *YandexFolderStruct, yandexInstances []*compute.Instance) []*YandexInstanceStruct {
	for _, instance := range yandexInstances {
		// Convert map[string]string to slice
		myLabels := convertMapToSlice(instance.Labels)
		Instances = append(Instances, &YandexInstanceStruct{
			ID:               instance.Id,
			Name:             instance.Name,
			Description:      instance.Description,
			CreatedAt:        instance.CreatedAt.String(),
			ZoneID:           instance.ZoneId,
			Labels:           myLabels,
			ParentFolderID:   folder.ID,
			ParentFolderName: folder.Name,
		})
	}
	return Instances
}

// GetYandexInstances - gets folders info for all provided clouds
func GetYandexInstances(ctx context.Context, sdk *yandexcloudsdk.SDK, folders []*YandexFolderStruct) ([]*YandexInstanceStruct, error) {
	theInstances := make([]*YandexInstanceStruct, 0)
	for _, folder := range folders {
		instances, err := sdk.Compute().Instance().List(ctx, &compute.ListInstancesRequest{
			FolderId: folder.ID,
			PageSize: yandexMaxPaginator,
		})
		if err != nil {
			return nil, err
		}
		theInstances = appendInstances(theInstances, folder, instances.Instances)
		for instances.NextPageToken != "" {
			instances, err = sdk.Compute().Instance().List(ctx, &compute.ListInstancesRequest{
				FolderId:  folder.ID,
				PageSize:  yandexMaxPaginator,
				PageToken: instances.NextPageToken,
			})
			if err != nil {
				return nil, err
			}
			theInstances = appendInstances(theInstances, folder, instances.Instances)
		}
	}
	return theInstances, nil
}

func appendMDBMySQL(MySQLs []*YandexMySQLStruct, folder *YandexFolderStruct, yandexMySQLs []*mysql.Cluster) []*YandexMySQLStruct {
	for _, thismysql := range yandexMySQLs {
		// Convert map[string]string to slice
		myLabels := convertMapToSlice(thismysql.Labels)
		MySQLs = append(MySQLs, &YandexMySQLStruct{
			ID:               thismysql.Id,
			Name:             thismysql.Name,
			Description:      thismysql.Description,
			CreatedAt:        thismysql.CreatedAt.String(),
			Labels:           myLabels,
			ParentFolderID:   folder.ID,
			ParentFolderName: folder.Name,
		})
	}
	return MySQLs
}

// GetYandexMySQLs - gets MySQLs MDB clusters info for all provided clouds
func GetYandexMySQLs(ctx context.Context, sdk *yandexcloudsdk.SDK, folders []*YandexFolderStruct) ([]*YandexMySQLStruct, error) {
	themySQLs := make([]*YandexMySQLStruct, 0)
	for _, folder := range folders {
		mySQLs, err := sdk.MDB().MySQL().Cluster().List(ctx, &mysql.ListClustersRequest{
			FolderId: folder.ID,
			PageSize: yandexMaxPaginator,
		})
		if err != nil {
			return nil, err
		}
		themySQLs = appendMDBMySQL(themySQLs, folder, mySQLs.Clusters)
		for mySQLs.NextPageToken != "" {
			mySQLs, err = sdk.MDB().MySQL().Cluster().List(ctx, &mysql.ListClustersRequest{
				FolderId:  folder.ID,
				PageSize:  yandexMaxPaginator,
				PageToken: mySQLs.NextPageToken,
			})
			if err != nil {
				return nil, err
			}
			themySQLs = appendMDBMySQL(themySQLs, folder, mySQLs.Clusters)
		}
	}
	return themySQLs, nil
}

func appendMDBMongoDB(MongoDBs []*YandexMongoDBStruct, folder *YandexFolderStruct, yandexMongoDBs []*mongodb.Cluster) []*YandexMongoDBStruct {
	for _, thismongodb := range yandexMongoDBs {
		// Convert map[string]string to slice
		myLabels := convertMapToSlice(thismongodb.Labels)
		MongoDBs = append(MongoDBs, &YandexMongoDBStruct{
			ID:               thismongodb.Id,
			Name:             thismongodb.Name,
			Description:      thismongodb.Description,
			CreatedAt:        thismongodb.CreatedAt.String(),
			Labels:           myLabels,
			ParentFolderID:   folder.ID,
			ParentFolderName: folder.Name,
		})
	}
	return MongoDBs
}

// GetYandexMongoDBs - gets MongoDB MDB clusters info for all provided clouds
func GetYandexMongoDBs(ctx context.Context, sdk *yandexcloudsdk.SDK, folders []*YandexFolderStruct) ([]*YandexMongoDBStruct, error) {
	theMDBs := make([]*YandexMongoDBStruct, 0)
	for _, folder := range folders {
		mongoDBs, err := sdk.MDB().MongoDB().Cluster().List(ctx, &mongodb.ListClustersRequest{
			FolderId: folder.ID,
			PageSize: yandexMaxPaginator,
		})
		if err != nil {
			return nil, err
		}
		theMDBs = appendMDBMongoDB(theMDBs, folder, mongoDBs.Clusters)
		for mongoDBs.NextPageToken != "" {
			mongoDBs, err = sdk.MDB().MongoDB().Cluster().List(ctx, &mongodb.ListClustersRequest{
				FolderId:  folder.ID,
				PageSize:  yandexMaxPaginator,
				PageToken: mongoDBs.NextPageToken,
			})
			if err != nil {
				return nil, err
			}
			theMDBs = appendMDBMongoDB(theMDBs, folder, mongoDBs.Clusters)
		}
	}
	return theMDBs, nil
}

func appendMDBPostgreSQL(PostgreSQLs []*YandexPostgreSQLStruct, folder *YandexFolderStruct, yandexPostgreSQLs []*postgresql.Cluster) []*YandexPostgreSQLStruct {
	for _, thismongodb := range yandexPostgreSQLs {
		// Convert map[string]string to slice
		myLabels := convertMapToSlice(thismongodb.Labels)
		PostgreSQLs = append(PostgreSQLs, &YandexPostgreSQLStruct{
			ID:               thismongodb.Id,
			Name:             thismongodb.Name,
			Description:      thismongodb.Description,
			CreatedAt:        thismongodb.CreatedAt.String(),
			Labels:           myLabels,
			ParentFolderID:   folder.ID,
			ParentFolderName: folder.Name,
		})
	}
	return PostgreSQLs
}

// GetYandexPostgreSQLs - gets PostgresDB MDB clusters info for all provided clouds
func GetYandexPostgreSQLs(ctx context.Context, sdk *yandexcloudsdk.SDK, folders []*YandexFolderStruct) ([]*YandexPostgreSQLStruct, error) {
	theMDBs := make([]*YandexPostgreSQLStruct, 0)
	for _, folder := range folders {
		postgreSQLs, err := sdk.MDB().PostgreSQL().Cluster().List(ctx, &postgresql.ListClustersRequest{
			FolderId: folder.ID,
			PageSize: yandexMaxPaginator,
		})
		if err != nil {
			return nil, err
		}
		theMDBs = appendMDBPostgreSQL(theMDBs, folder, postgreSQLs.Clusters)
		for postgreSQLs.NextPageToken != "" {
			postgreSQLs, err = sdk.MDB().PostgreSQL().Cluster().List(ctx, &postgresql.ListClustersRequest{
				FolderId:  folder.ID,
				PageSize:  yandexMaxPaginator,
				PageToken: postgreSQLs.NextPageToken,
			})
			if err != nil {
				return nil, err
			}
			theMDBs = appendMDBPostgreSQL(theMDBs, folder, postgreSQLs.Clusters)
		}
	}
	return theMDBs, nil
}

func appendMDBRedis(MDBs []*YandexRedisStruct, folder *YandexFolderStruct, yandexMDBs []*redis.Cluster) []*YandexRedisStruct {
	for _, thismbd := range yandexMDBs {
		// Convert map[string]string to slice
		myLabels := convertMapToSlice(thismbd.Labels)
		MDBs = append(MDBs, &YandexRedisStruct{
			ID:               thismbd.Id,
			Name:             thismbd.Name,
			Description:      thismbd.Description,
			CreatedAt:        thismbd.CreatedAt.String(),
			Labels:           myLabels,
			ParentFolderID:   folder.ID,
			ParentFolderName: folder.Name,
		})
	}
	return MDBs
}

// GetYandexRedises - gets Redis MDB clusters info for all provided clouds
func GetYandexRedises(ctx context.Context, sdk *yandexcloudsdk.SDK, folders []*YandexFolderStruct) ([]*YandexRedisStruct, error) {
	theMDBs := make([]*YandexRedisStruct, 0)
	for _, folder := range folders {
		Redises, err := sdk.MDB().Redis().Cluster().List(ctx, &redis.ListClustersRequest{
			FolderId: folder.ID,
			PageSize: yandexMaxPaginator,
		})
		if err != nil {
			return nil, err
		}
		theMDBs = appendMDBRedis(theMDBs, folder, Redises.Clusters)
		for Redises.NextPageToken != "" {
			Redises, err = sdk.MDB().Redis().Cluster().List(ctx, &redis.ListClustersRequest{
				FolderId:  folder.ID,
				PageSize:  yandexMaxPaginator,
				PageToken: Redises.NextPageToken,
			})
			if err != nil {
				return nil, err
			}
			theMDBs = appendMDBRedis(theMDBs, folder, Redises.Clusters)
		}
	}
	return theMDBs, nil
}

func appendMDBClickHouse(MDBs []*YandexClickHouseStruct, folder *YandexFolderStruct, yandexMDBs []*clickhouse.Cluster) []*YandexClickHouseStruct {
	for _, thismbd := range yandexMDBs {
		// Convert map[string]string to slice
		myLabels := convertMapToSlice(thismbd.Labels)
		MDBs = append(MDBs, &YandexClickHouseStruct{
			ID:               thismbd.Id,
			Name:             thismbd.Name,
			Description:      thismbd.Description,
			CreatedAt:        thismbd.CreatedAt.String(),
			Labels:           myLabels,
			ParentFolderID:   folder.ID,
			ParentFolderName: folder.Name,
		})
	}
	return MDBs
}

// GetYandexClickHouses - gets ClickHouses MDB clusters info for all provided Folders
func GetYandexClickHouses(ctx context.Context, sdk *yandexcloudsdk.SDK, folders []*YandexFolderStruct) ([]*YandexClickHouseStruct, error) {
	theMDBs := make([]*YandexClickHouseStruct, 0)
	for _, folder := range folders {
		ClickHouses, err := sdk.MDB().Clickhouse().Cluster().List(ctx, &clickhouse.ListClustersRequest{
			FolderId: folder.ID,
			PageSize: yandexMaxPaginator,
		})
		if err != nil {
			return nil, err
		}
		theMDBs = appendMDBClickHouse(theMDBs, folder, ClickHouses.Clusters)
		for ClickHouses.NextPageToken != "" {
			ClickHouses, err = sdk.MDB().Clickhouse().Cluster().List(ctx, &clickhouse.ListClustersRequest{
				FolderId:  folder.ID,
				PageSize:  yandexMaxPaginator,
				PageToken: ClickHouses.NextPageToken,
			})
			if err != nil {
				return nil, err
			}
			theMDBs = appendMDBClickHouse(theMDBs, folder, ClickHouses.Clusters)
		}
	}
	return theMDBs, nil
}

func appendDisk(Disks []*YandexDiskStruct, folder *YandexFolderStruct, yandexDisks []*compute.Disk) []*YandexDiskStruct {
	for _, thisdisk := range yandexDisks {
		// Convert map[string]string to slice
		myLabels := convertMapToSlice(thisdisk.Labels)
		Disks = append(Disks, &YandexDiskStruct{
			ID:               thisdisk.Id,
			Name:             thisdisk.Name,
			Description:      thisdisk.Description,
			CreatedAt:        thisdisk.CreatedAt.String(),
			Labels:           myLabels,
			ParentFolderID:   folder.ID,
			ParentFolderName: folder.Name,
		})
	}
	return Disks
}

// GetYandexDisks - gets Disks info for all provided folders
func GetYandexDisks(ctx context.Context, sdk *yandexcloudsdk.SDK, folders []*YandexFolderStruct) ([]*YandexDiskStruct, error) {
	theDisks := make([]*YandexDiskStruct, 0)
	for _, folder := range folders {
		Disks, err := sdk.Compute().Disk().List(ctx, &compute.ListDisksRequest{
			FolderId: folder.ID,
			PageSize: yandexMaxPaginator,
		})
		if err != nil {
			return nil, err
		}
		theDisks = appendDisk(theDisks, folder, Disks.Disks)
		for Disks.NextPageToken != "" {
			Disks, err = sdk.Compute().Disk().List(ctx, &compute.ListDisksRequest{
				FolderId:  folder.ID,
				PageSize:  yandexMaxPaginator,
				PageToken: Disks.NextPageToken,
			})
			if err != nil {
				return nil, err
			}
			theDisks = appendDisk(theDisks, folder, Disks.Disks)
		}
	}
	return theDisks, nil
}

// AWS-alike collection of data is not possible unless you have keypair for each bucket or folder.

// GetYandexCloudMap - Gets Yandex Cloud Map with provided credentials
func GetYandexCloudMap(keyFile []byte) *YandexClouds {
	// File is legacy before vault - must be customized for vault
	YandexSDK, err := InitYandexSDK(keyFile)
	if err != nil {
		log.Panic(err.Error())
	}
	clouds, err := GetYandexClouds(context.Background(), YandexSDK)
	if err != nil {
		log.Panic(err.Error())
	}
	folders, err := GetYandexFolders(context.Background(), YandexSDK, clouds)
	if err != nil {
		log.Panic(err.Error())
	}
	instances, err := GetYandexInstances(context.Background(), YandexSDK, folders)
	if err != nil {
		log.Panic(err.Error())
	}
	for _, instance := range instances {
		log.Debug(instance.ParentFolderName + " " + instance.Name + " ")
		log.Debug(instance.Labels)
	}
	mysqls, err := GetYandexMySQLs(context.Background(), YandexSDK, folders)
	if err != nil {
		log.Panic(err.Error())
	}
	for _, mysql := range mysqls {
		log.Debug(mysql.ParentFolderName + " " + mysql.Name)
		log.Debug(mysql.Labels)
	}
	mongodbs, err := GetYandexMongoDBs(context.Background(), YandexSDK, folders)
	if err != nil {
		log.Panic(err.Error())
	}
	for _, mongodb := range mongodbs {
		log.Debug(mongodb.ParentFolderName + " " + mongodb.Name)
		log.Debug(mongodb.Labels)
	}
	postgresdbs, err := GetYandexPostgreSQLs(context.Background(), YandexSDK, folders)
	if err != nil {
		log.Panic(err.Error())
	}
	for _, postgresdb := range postgresdbs {
		log.Debug(postgresdb.ParentFolderName + " " + postgresdb.Name)
		log.Debug(postgresdb.Labels)
	}
	redises, err := GetYandexRedises(context.Background(), YandexSDK, folders)
	if err != nil {
		log.Panic(err.Error())
	}
	for _, redis := range redises {
		log.Debug(redis.ParentFolderName + " " + redis.Name)
		log.Debug(redis.Labels)
	}
	clickhouses, err := GetYandexClickHouses(context.Background(), YandexSDK, folders)
	if err != nil {
		log.Panic(err.Error())
	}
	for _, clickhouse := range clickhouses {
		log.Debug(clickhouse.ParentFolderName + " " + clickhouse.Name)
		log.Debug(clickhouse.Labels)
	}
	disks, err := GetYandexDisks(context.Background(), YandexSDK, folders)
	if err != nil {
		log.Panic(err.Error())
	}
	for _, disk := range disks {
		log.Debug(disk.ParentFolderName + " " + disk.Name)
		log.Debug(disk.Labels)
	}
	YandexCloud := &YandexClouds{
		Clouds:        clouds,
		Folders:       folders,
		Instances:     instances,
		Disks:         disks,
		MDBMySQL:      mysqls,
		MDBMongoDB:    mongodbs,
		MDBPostgreSQL: postgresdbs,
		MBDRedis:      redises,
		MDBClickHouse: clickhouses,
	}
	return YandexCloud
}
