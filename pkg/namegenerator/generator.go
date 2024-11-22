package namegenerator

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

type Generator interface {
	Generate() (string, error)
}

type NameGenerator struct {
	random *int64
}

func (rn *NameGenerator) Generate() (string, error) {
	seed, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		return "", fmt.Errorf("%v", err.Error())
	}

	randomName := FULLNAMES[seed.Int64()]
	return strings.ReplaceAll(randomName, " ", ""), nil
}

func NewNameGenerator(seed int64) Generator {
	nameGenerator := &NameGenerator{
		random: &seed,
	}
	return nameGenerator
}
