package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Ipfix struct {
	Address          string `yaml:"address"`
	Port             string `yaml:"port"`
	IngressInterface string `yaml:"ingress-interface"`
	Interval         int    `yaml:"interval"`
}

type Config struct {
	Ipfix Ipfix `yaml:"ipfix"`
}

func ReadConfigFile(configFile string) (Config, error) {
	c := &Config{}

	f, err := os.Open(configFile)
	if err != nil {
		return *c, err
	}
	defer f.Close()

	if err := yaml.NewDecoder(f).Decode(c); err != nil {
		return *c, err
	}
	return *c, nil
}
