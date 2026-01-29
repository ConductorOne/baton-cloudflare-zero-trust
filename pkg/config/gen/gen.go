package main

import (
	cfg "github.com/conductorone/baton-cloudflare-zero-trust/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
)

func main() {
	config.Generate("cloudflare-zero-trust", cfg.Config)
}
