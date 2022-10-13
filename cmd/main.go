package main

import (
	"github.com/go-echarts/statsview"

	"github.com/yaproxy/yap"
)

func main() {
	mgr := statsview.New()

	// Start() runs a HTTP server at `localhost:18066` by default.
	go mgr.Start()
	yap.Main()
}
