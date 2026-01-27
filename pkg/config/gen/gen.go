package main

import (
	"github.com/conductorone/baton-sdk/pkg/config"
	cfg "github.com/conductorone/baton-cloudflare-zero-trust/pkg/config"
)

func main() {
	config.Generate("cloudflare-zero-trust", cfg.Config)
}
