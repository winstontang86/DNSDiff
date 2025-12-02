package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestDefaultLogConfig(t *testing.T) {
	config := DefaultLogConfig()

	if config == nil {
		t.Fatal("DefaultLogConfig returned nil")
	}

	if config.Level != "info" {
		t.Errorf("Expected Level to be 'info', got '%s'", config.Level)
	}

	if config.Filename != "log/udns_dial.log" {
		t.Errorf("Expected Filename to be 'log/udns_dial.log', got '%s'", config.Filename)
	}

	if config.MaxSize != 100 {
		t.Errorf("Expected MaxSize to be 100, got %d", config.MaxSize)
	}

	if config.MaxBackups != 5 {
		t.Errorf("Expected MaxBackups to be 5, got %d", config.MaxBackups)
	}
}

func TestInitLogger(t *testing.T) {
	// Create temporary directory for test logs
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	tests := []struct {
		name          string
		config        *LogConfig
		expectedLevel logrus.Level
	}{
		{
			name:          "nil config uses default",
			config:        nil,
			expectedLevel: logrus.InfoLevel,
		},
		{
			name: "debug level",
			config: &LogConfig{
				Level:      "debug",
				Filename:   logFile,
				MaxSize:    50,
				MaxBackups: 3,
			},
			expectedLevel: logrus.DebugLevel,
		},
		{
			name: "info level",
			config: &LogConfig{
				Level:      "info",
				Filename:   logFile,
				MaxSize:    50,
				MaxBackups: 3,
			},
			expectedLevel: logrus.InfoLevel,
		},
		{
			name: "warn level",
			config: &LogConfig{
				Level:      "warn",
				Filename:   logFile,
				MaxSize:    50,
				MaxBackups: 3,
			},
			expectedLevel: logrus.WarnLevel,
		},
		{
			name: "error level",
			config: &LogConfig{
				Level:      "error",
				Filename:   logFile,
				MaxSize:    50,
				MaxBackups: 3,
			},
			expectedLevel: logrus.ErrorLevel,
		},
		{
			name: "invalid level defaults to info",
			config: &LogConfig{
				Level:      "invalid",
				Filename:   logFile,
				MaxSize:    50,
				MaxBackups: 3,
			},
			expectedLevel: logrus.InfoLevel,
		},
		{
			name: "empty level defaults to info",
			config: &LogConfig{
				Level:      "",
				Filename:   logFile,
				MaxSize:    50,
				MaxBackups: 3,
			},
			expectedLevel: logrus.InfoLevel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize logger
			InitLogger(tt.config)

			// Check log level
			if logrus.GetLevel() != tt.expectedLevel {
				t.Errorf("Expected log level %v, got %v", tt.expectedLevel, logrus.GetLevel())
			}

			// Verify formatter is JSON
			if _, ok := logrus.StandardLogger().Formatter.(*logrus.JSONFormatter); !ok {
				t.Error("Expected formatter to be JSONFormatter")
			}
		})
	}
}

func TestInitLogger_CreatesLogDirectory(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	logDir := filepath.Join(tempDir, "logs", "subdir")
	logFile := filepath.Join(logDir, "test.log")

	config := &LogConfig{
		Level:      "info",
		Filename:   logFile,
		MaxSize:    50,
		MaxBackups: 3,
	}

	// Initialize logger (lumberjack should create directory)
	InitLogger(config)

	// Write a log entry to trigger file creation
	logrus.Info("Test log entry")

	// Note: lumberjack.Logger creates directories automatically
	// We just verify no panic occurred
}

func TestLogConfig_CustomValues(t *testing.T) {
	tests := []struct {
		name       string
		config     *LogConfig
		wantLevel  string
		wantFile   string
		wantSize   int
		wantBackup int
	}{
		{
			name: "custom config 1",
			config: &LogConfig{
				Level:      "debug",
				Filename:   "/tmp/custom.log",
				MaxSize:    200,
				MaxBackups: 10,
			},
			wantLevel:  "debug",
			wantFile:   "/tmp/custom.log",
			wantSize:   200,
			wantBackup: 10,
		},
		{
			name: "custom config 2",
			config: &LogConfig{
				Level:      "error",
				Filename:   "app.log",
				MaxSize:    1,
				MaxBackups: 1,
			},
			wantLevel:  "error",
			wantFile:   "app.log",
			wantSize:   1,
			wantBackup: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.Level != tt.wantLevel {
				t.Errorf("Level = %v, want %v", tt.config.Level, tt.wantLevel)
			}
			if tt.config.Filename != tt.wantFile {
				t.Errorf("Filename = %v, want %v", tt.config.Filename, tt.wantFile)
			}
			if tt.config.MaxSize != tt.wantSize {
				t.Errorf("MaxSize = %v, want %v", tt.config.MaxSize, tt.wantSize)
			}
			if tt.config.MaxBackups != tt.wantBackup {
				t.Errorf("MaxBackups = %v, want %v", tt.config.MaxBackups, tt.wantBackup)
			}
		})
	}
}

func TestInitLogger_Integration(t *testing.T) {
	// Create temporary log file
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "integration.log")

	config := &LogConfig{
		Level:      "debug",
		Filename:   logFile,
		MaxSize:    10,
		MaxBackups: 2,
	}

	// Initialize logger
	InitLogger(config)

	// Write various log levels
	logrus.Debug("Debug message")
	logrus.Info("Info message")
	logrus.Warn("Warning message")
	logrus.Error("Error message")

	// Verify log file was created
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Errorf("Log file was not created: %s", logFile)
	}
}

func BenchmarkDefaultLogConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = DefaultLogConfig()
	}
}

func BenchmarkInitLogger(b *testing.B) {
	tempDir := b.TempDir()
	logFile := filepath.Join(tempDir, "bench.log")

	config := &LogConfig{
		Level:      "info",
		Filename:   logFile,
		MaxSize:    50,
		MaxBackups: 3,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InitLogger(config)
	}
}
