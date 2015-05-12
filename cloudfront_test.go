package cloudfront

import (
	"fmt"
	"testing"
	"time"
)

func TestMain(t *testing.T) {
	expected := time.Now().Add(10*time.Minute)
	
	conds := conditions{
		DateLessThan: epochTime{
			expected.Truncate(time.Millisecond).Unix(),
		},
	}

	text, _ := buildPolicy("Test", conds)
	fmt.Println(string(text))
}