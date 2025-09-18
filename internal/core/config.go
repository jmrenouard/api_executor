package core

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Logging   LoggingConfig   `yaml:"logging"`
	Database  DatabaseConfig  `yaml:"database"`
	FileServer FileServerConfig `yaml:"file_server"`
	Executor  ExecutorConfig  `yaml:"command_executor"`
}

type ServerConfig struct {
	Port int    `yaml:"port"`
	Host string `yaml:"host"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
	Path  string `yaml:"path"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type FileServerConfig struct {
	Enabled   bool   `yaml:"enabled"`
	SecureDir string `yaml:"secure_dir"`
}

type ExecutorConfig struct {
	Enabled  bool              `yaml:"enabled"`
	Commands []CommandDefinition `yaml:"commands"`
}

type CommandDefinition struct {
	Name    string   `yaml:"name"`
	Command string   `yaml:"command"`
	Args    []string `yaml:"args"`
}

func LoadConfig(path string) (*Config, error) {
	config := &Config{}

	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(file, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}
