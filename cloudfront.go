package cloudfront

import (
        "crypto/rsa"
        "encoding/base64"
        "encoding/json"
        "strings"
)

type CloudFront struct {
        baseURL   string
        keyPairId string
        key       *rsa.PrivateKey
}

type policy struct {
        Statement []statement
}

type statement struct {
        Resource  string
        Condition conditions
}

type conditions struct {
        DateLessThan    epochTime
        DateGreaterThan *epochTime `json:",omitempty"`
        IpAddress       *ipAddress  `json:",omitempty"`
}

type epochTime struct {
        Timestamp int64 `json:"AWS:EpochTime"`
}

type ipAddress struct {
        Addr string `json:"AWS:SourceIp"`
}

// Will convert values from base64 encoded string to be URL safe
var invalidReplacer = strings.NewReplacer("+", "-", "=", "_", "/", "~")

func New(baseurl string, key *rsa.PrivateKey, keyPairId string) *CloudFront {
        return &CloudFront{
                baseURL:   baseurl,
                keyPairId: keyPairId,
                key:       key,
        }
}

func buildPolicy(resource string, conditions conditions) ([]byte, error) {
    p := &policy{
        Statement: []statement{
            statement{
                Resource: resource,
                Condition: conditions,
            },
        },
    }
    
    return json.Marshal(p)
}

// Helper to make a slice-o-bytes query string safe
func queryize(policy []byte) string {
    return invalidReplacer.Replace(base64.StdEncoding.EncodeToString(policy))
}