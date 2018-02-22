package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"

	log "github.com/inconshreveable/log15"
	yaml "gopkg.in/yaml.v2"
)

// Config for reverse proxy settings and RBAC users and groups
// Unmarshalled from config on disk
type Config struct {
	ListenInterface string `yaml:"listen_interface"`
	ListenPort      int    `yaml:"listen_port"`
	Target          string
	JSONlogging     bool   `yaml:"json_logging"`
	AnonymousGroup  string `yaml:"anonymous_group"`
	GroupHeaderName string `yaml:"group_header_name"`
	GroupHeaderType string `yaml:"group_header_type"`
	UserHeaderName  string `yaml:"user_header_name"`
	RBAC            struct {
		Groups map[string]Permissions
	}
}

func (C *Config) getConf() *Config {

	pwd, _ := os.Getwd()
	yamlFile, err := ioutil.ReadFile(path.Join(pwd, "config.yaml"))
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	err = yaml.Unmarshal(yamlFile, C)
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}

	return C
}

func main() {
	var C Config
	C.getConf()

	proxy := NewProx(&C)

	http.HandleFunc("/", proxy.handleRequest)
	http.ListenAndServe(fmt.Sprintf("%s:%d", C.ListenInterface, C.ListenPort), nil)
}
