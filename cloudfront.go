package cloudfront

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type CloudFront struct {
	domain    string
	KeyPairId string
	key       *rsa.PrivateKey
}

type Policy struct {
	policy []byte
	cf     *CloudFront
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
	IpAddress       *ipAddress `json:",omitempty"`
}

type epochTime struct {
	Timestamp int64 `json:"AWS:EpochTime"`
}

type ipAddress struct {
	Addr string `json:"AWS:SourceIp"`
}

// Will convert values from base64 encoded string to be URL safe
var invalidReplacer = strings.NewReplacer("+", "-", "=", "_", "/", "~")

var ErrMissingRequiredParam = errors.New("Missing required parameter")

func New(key *rsa.PrivateKey, keyPairId string) *CloudFront {
	return &CloudFront{
		KeyPairId: keyPairId,
		key:       key,
	}
}

func (p Policy) Encode() string {
	return invalidReplacer.Replace(base64.StdEncoding.EncodeToString(p.policy))
}

func (p Policy) Sign() (string, error) {
	hash := hashSha(p.policy)
	signed, err := rsa.SignPKCS1v15(nil, p.cf.key, crypto.SHA1, hash)
	if err != nil {
		return "", err
	}

	return invalidReplacer.Replace(base64.StdEncoding.EncodeToString(signed)), nil
}

func (cf *CloudFront) CreatePolicy(resource string, expiry time.Time, validAt *time.Time, ip *string) (Policy, error) {
	if expiry.IsZero() {
		return nil, ErrMissingRequiredParam
	}

	conds := conditions{
		DateLessThan: epochTime{
			Timestamp: expiry.Truncate(time.Millisecond).Unix(),
		},
	}

	if validAt != nil {
		conds.DateGreaterThan = &epochTime{
			Timestamp: *validAt.Truncate(time.Millisecond).Unix(),
		}
	}

	if ip != nil {
		conds.IpAddress = &ipAddress{
			Addr: *ip,
		}
	}

	policy, err := buildPolicy(resource, conds)
	if err != nil {
		return nil, err
	}

	return Policy{cf: cf, policy: policy}, nil
}

func hashSha(policy []byte) []byte {
	hash := sha1.New()
	hash.Write(p.policy)
	hash.Sum(nil)
}

func buildPolicy(resource string, conditions conditions) ([]byte, error) {
	p := &policy{
		Statement: []statement{
			statement{
				Resource:  resource,
				Condition: conditions,
			},
		},
	}

	return json.Marshal(p)
}
