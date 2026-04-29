package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/venkatkrishna07/caddy-mcp"
)

func main() {
	caddycmd.Main()
}
