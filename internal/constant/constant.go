package constant

import (
	"encoding/json"
	"github.com/joho/godotenv"
	"os"
)

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// sort on sequence
type Sort struct {
	DbName string `json:"db_name"`
	Type   string `json:"type"`
}

func SetSort(field, sortType string) string {
	sorts := make([]Sort, 1)
	sortField := Sort{
		DbName: field,
		Type:   sortType, // asc,des
	}
	sorts[0] = sortField
	jsonSort, _ := json.Marshal(sorts)
	return string(jsonSort)
}

// status
const (
	DeleteStatus = iota - 1
	InactiveStatus
	ActiveStatus
	RequestToActiveStatus
)

const (
	DraftEnabledEntityDeleteStatus = iota - 1
	DraftEnabledEntityDraftStatus
	DraftEnabledEntityActiveStatus
	DraftEnabledEntityRequestToApproveStatus
	DraftEnabledEntityApproveStatus
	DraftEnabledEntityInActiveStatus
	DraftEnabledEntityRejectStatus
	DraftEnabledEntitySuspendStatus
	DraftEnabledEntityCancelStatus
	DraftEnabledEntityArchiveStatus
)

// collection Name
const (
	ChallengeCollection = "challenges"
	SolutionCollection  = "solutions"
)

// message key
const (
	Inserted = "REF.INSERTED"
	Updated  = "REF.UPDATED"
	Deleted  = "REF.DELETED"
)

// service info
const (
	ServiceName    = "challenge"
	ServiceVersion = "1.0.0"
)

func getEnv(key string) string {
	_ = godotenv.Load(".env")
	return os.Getenv(key)
}

// env
var (
	HttpPort        = getEnv("http_port")
	MongoDbUsername = getEnv("mongodb_username")
	MongoPassword   = getEnv("mongodb_password")
	MongoAddr       = getEnv("mongodb_addr")
	MongoDatabase   = getEnv("mongodb_database")
	MongoTimeout    = getEnv("mongodb_timeout")

	KeyDbConnection = getEnv("keydb_connection")
	KeyDbDatabaseNo = getEnv("keydb_database")
	KeyDbPassword   = getEnv("keydb_password")
	KeyDbUsername   = getEnv("keydb_username")
)

var (
	DraftEnabledEntityStatusMap = map[string]int{
		"draft":            DraftEnabledEntityDraftStatus,
		"active":           DraftEnabledEntityActiveStatus,
		"requestToApprove": DraftEnabledEntityRequestToApproveStatus,
		"approve":          DraftEnabledEntityApproveStatus,
		"inactive":         DraftEnabledEntityInActiveStatus,
		"suspend":          DraftEnabledEntitySuspendStatus,
		"reject":           DraftEnabledEntityRejectStatus,
		"archive":          DraftEnabledEntityArchiveStatus,
	}
)
