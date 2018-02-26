package main

import (
	"flag"
	"io/ioutil"
	"log"

	"github.com/docker/go-plugins-helpers/authorization"
)

func main() {
	var err error

	var tcp = flag.String("tcp", "", "listen TCP (e.g. '127.0.0.1:8080')")
	var unix = flag.String("unix", "", "listen unix domain socket")
	var unixGid = flag.Int("unix-gid", 0, "unix domain socker gid")
	var ruleFile = flag.String("rule", "", "path to rule file")
	var daemonDir = flag.String("daemon-dir", "", "Docker daemon dir")
	flag.Parse()

	if *ruleFile == "" {
		log.Fatal("-rule option is mandatory")
	}
	if (*tcp != "" && *unix != "") || (*tcp == "" && *unix == "") {
		log.Fatal("please specify either -tcp or -unix")
	}

	ruleBytes, err := ioutil.ReadFile(*ruleFile)
	if err != nil {
		log.Fatal(err)
	}

	p := NewPlugin(string(ruleBytes))
	h := authorization.NewHandler(p)
	if *tcp != "" {
		log.Printf("Listening TCP %s", *tcp)
		err = h.ServeTCP("docker-authz-mruby", *tcp, *daemonDir, nil)
	} else if *unix != "" {
		log.Printf("Listening unix socket %s", *unix)
		err = h.ServeUnix(*unix, *unixGid)
	}

	if err != nil {
		log.Fatal(err)
	}
}
