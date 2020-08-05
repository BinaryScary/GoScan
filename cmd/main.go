package main

import (
	"flag"

	"github.com/BinaryScary/goscan"
)

func main() {
	options := &goscan.Options{}

	flag.StringVar(&options.Range, "r", "", "IP/CIDR Range (Required)")
	flag.StringVar(&options.Ports, "p", "22, 53, 66, 80, 81, 445, 457, 1080, 1100, 1241, 1352, 1433, 1434, 1521, 1944, 2301, 3128, 3306, 4000, 4001, 4002, 4100, 5000, 5432, 5800, 5801, 5802, 6346, 6347, 7001, 7002, 8080, 8888, 30821", "Comma separated ports")
	flag.IntVar(&options.Timeout, "t", 10, "Timeout after request is sent")
	flag.IntVar(&options.Requests, "c", 500, "Requests per second")
	flag.Parse()

	if options.Range == "" {
		flag.Usage()
		return
	}

	goscan.Run(options)
}
