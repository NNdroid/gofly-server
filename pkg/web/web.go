package web

import "embed"

//go:embed index.html css/* fonts/* js/* lib/*
var StaticFS embed.FS
