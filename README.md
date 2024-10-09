# goxy

Reverse proxy that hides the origins written in Go.

## Usage

### Server

```bash
go run server/main.go -port <PORT> -domain <DOMAIN> -email <EMAIL> -cloudflare-api-token <CLOUDFLARE_API_TOKEN>
```

### Client

```bash
go run client/main.go -proxy-address <PROXY_ADDRESS> -origin-address <ORIGIN_ADDRESS> -subdomain <SUBDOMAIN> -password <PASSWORD>
```

### Origin

```bash
go run origin/main.go -port <PORT>
```
