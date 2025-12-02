package app

import (
	"github.com/natefinch/lumberjack"
	"github.com/sirupsen/logrus"
)

// LogConfig 日志配置
type LogConfig struct {
	Level      string // 日志级别: debug, info, warn, error
	Filename   string // 日志文件路径
	MaxSize    int    // 每个日志文件的最大大小（MB）
	MaxBackups int    // 保留的最大日志文件数量
}

// DefaultLogConfig 返回默认日志配置
func DefaultLogConfig() *LogConfig {
	return &LogConfig{
		Level:      "info",
		Filename:   "log/udns_dial.log",
		MaxSize:    100,
		MaxBackups: 5,
	}
}

// InitLogger 初始化日志系统
func InitLogger(config *LogConfig) {
	if config == nil {
		config = DefaultLogConfig()
	}

	// 设置日志输出
	logrus.SetOutput(&lumberjack.Logger{
		Filename:   config.Filename,
		MaxSize:    config.MaxSize,
		MaxBackups: config.MaxBackups,
	})

	// 设置日志级别
	switch config.Level {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "warn":
		logrus.SetLevel(logrus.WarnLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}

	// 设置日志格式为JSON
	logrus.SetFormatter(&logrus.JSONFormatter{})
}
