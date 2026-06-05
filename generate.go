package main

//go:generate go tool openapi overlay apply --overlay ./overlay.yml --schema ./third_party/passbolt-openapi/openapi.yaml --out ./third_party/passbolt-openapi/openapi-3.0.yaml
//go:generate go tool oapi-codegen --config ./codegen.yml ./third_party/passbolt-openapi/openapi-3.0.yaml
