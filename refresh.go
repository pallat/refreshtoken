package refreshtoken

import (
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	hmacSampleSecret = "qvjqnhzu8LMWDCmu7MgvDpaMWsASAmhd"
)

type tokenizer interface {
	Get() (jwtToken, error)
}

type tokenize struct {
	t           tokenizer
	tokenString string
	mux         *sync.Mutex
}

func Tokenize() *tokenize {
	t := &tokenize{
		t:           &tokenClient{lifeTime: 1},
		tokenString: "",
		mux:         &sync.Mutex{},
	}

	go t.Start()

	return t
}

func (t *tokenize) Save(s string) {
	t.mux.Lock()
	defer t.mux.Unlock()
	t.tokenString = s
}

func (t *tokenize) Start() {
	token, _ := t.t.Get()
	t.Save(token.TokenString)

	marking := token.ExpiresAt

	for range time.Tick(time.Duration(marking) - (500 * time.Millisecond)) {
		token, _ := t.t.Get()
		t.Save(token.TokenString)
	}
}

func (t *tokenize) Token() string {
	t.mux.Lock()
	defer t.mux.Unlock()
	return t.tokenString
}

type tokenClient struct {
	lifeTime time.Duration
}

type jwtToken struct {
	TokenString string `json:"tokenString"`
	ExpiresAt   int64  `json:"expiresAt"`
}

func (t *tokenClient) Get() (jwtToken, error) {
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(t.lifeTime * time.Second).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(hmacSampleSecret))
	// Sign and get the complete encoded token as a string using the secret
	return jwtToken{
		TokenString: tokenString,
		ExpiresAt:   claims.ExpiresAt,
	}, err
}
