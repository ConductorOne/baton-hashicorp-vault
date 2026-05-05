package main

import (
	cfg "github.com/conductorone/baton-hashicorp-vault/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
)

func main() {
	config.Generate("hashicorp-vault", cfg.Config)
}
