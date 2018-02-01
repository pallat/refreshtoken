package refreshtoken

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type fakeTokenClient struct{}

func (fakeTokenClient) Get() (jwtToken, error) {
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(1 * time.Second).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(hmacSampleSecret))
	// Sign and get the complete encoded token as a string using the secret
	return jwtToken{
		TokenString: tokenString,
		ExpiresAt:   claims.ExpiresAt,
	}, err
}

func TestGetToken(t *testing.T) {
	tkn := tokenize{
		t:           &fakeTokenClient{},
		tokenString: "",
		mux:         &sync.RWMutex{},
	}

	go tkn.Start()
	<-time.After(200 * time.Millisecond)

	tk := tkn.Token()
	if tk == "" {
		t.Error("it should return someting like token")
	}
}

func TestGetTokenExpiredShouldRefreshAutomaticly(t *testing.T) {
	tkn := tokenize{
		t:           &fakeTokenClient{},
		tokenString: "",
		mux:         &sync.RWMutex{},
	}

	go tkn.Start()

	tokenString := tkn.Token()
	fmt.Println(tokenString)

	<-time.After(2 * time.Second)
	tokenString = tkn.Token()
	fmt.Println(tokenString)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(hmacSampleSecret), nil
	})

	fmt.Println(token, err)
}
