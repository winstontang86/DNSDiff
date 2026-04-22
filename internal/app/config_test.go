package app

import (
	"dnsdiff/internal/diff"
	"testing"
)

func TestDefaultCompareConfig(t *testing.T) {
	config := DefaultCompareConfig()

	if config == nil {
		t.Fatal("DefaultCompareConfig returned nil")
	}

	if !config.AllowPartialMatch {
		t.Error("Expected AllowPartialMatch to be true")
	}

	if !config.IgnoreAdditional {
		t.Error("Expected IgnoreAdditional to be true")
	}

	if config.DiffUnexpectedMask != diff.DefaultMask {
		t.Errorf("Expected DiffUnexpectedMask to be %d, got %d", diff.DefaultMask, config.DiffUnexpectedMask)
	}
}

func TestParseHexMask(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint32
		wantErr bool
	}{
		{
			name:    "valid hex with 0x prefix",
			input:   "0x00000001",
			want:    0x00000001,
			wantErr: false,
		},
		{
			name:    "valid hex without 0x prefix",
			input:   "00000001",
			want:    0x00000001,
			wantErr: false,
		},
		{
			name:    "valid hex uppercase",
			input:   "0xFFFFFFFF",
			want:    0xFFFFFFFF,
			wantErr: false,
		},
		{
			name:    "valid hex lowercase",
			input:   "0xffffffff",
			want:    0xffffffff,
			wantErr: false,
		},
		{
			name:    "valid hex mixed case",
			input:   "0xAbCdEf12",
			want:    0xAbCdEf12,
			wantErr: false,
		},
		{
			name:    "zero value",
			input:   "0x00000000",
			want:    0x00000000,
			wantErr: false,
		},
		{
			name:    "short hex",
			input:   "0x1",
			want:    0x1,
			wantErr: false,
		},
		{
			name:    "invalid hex - contains g",
			input:   "0xGGGGGGGG",
			want:    0,
			wantErr: true,
		},
		{
			name:    "invalid hex - empty string",
			input:   "",
			want:    0,
			wantErr: true,
		},
		{
			name:    "invalid hex - only 0x",
			input:   "0x",
			want:    0,
			wantErr: true,
		},
		{
			name:    "invalid hex - non-hex characters",
			input:   "0xZZZZ",
			want:    0,
			wantErr: true,
		},
		{
			name:    "invalid hex - special characters",
			input:   "0x@#$%",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHexMask(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseHexMask() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseHexMask() = 0x%08X, want 0x%08X", got, tt.want)
			}
		})
	}
}

func TestCompareConfig_ToComparator(t *testing.T) {
	tests := []struct {
		name   string
		config *CompareConfig
	}{
		{
			name: "default config",
			config: &CompareConfig{
				AllowPartialMatch:  true,
				IgnoreAdditional:   true,
				DiffUnexpectedMask: diff.DefaultMask,
			},
		},
		{
			name: "all false config",
			config: &CompareConfig{
				AllowPartialMatch:  false,
				IgnoreAdditional:   false,
				DiffUnexpectedMask: 0x00000000,
			},
		},
		{
			name: "custom mask config",
			config: &CompareConfig{
				AllowPartialMatch:  false,
				IgnoreAdditional:   true,
				DiffUnexpectedMask: 0xFFFFFFFF,
			},
		},
		{
			name: "mixed config",
			config: &CompareConfig{
				AllowPartialMatch:  true,
				IgnoreAdditional:   false,
				DiffUnexpectedMask: 0x12345678,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comparator := tt.config.ToComparator()

			if comparator.IgnoreAdditional != tt.config.IgnoreAdditional {
				t.Errorf("IgnoreAdditional = %v, want %v", comparator.IgnoreAdditional, tt.config.IgnoreAdditional)
			}

			if comparator.DiffUnexpectedMask != tt.config.DiffUnexpectedMask {
				t.Errorf("DiffUnexpectedMask = 0x%08X, want 0x%08X", comparator.DiffUnexpectedMask, tt.config.DiffUnexpectedMask)
			}

			// WhitelistChecker should be nil as it's not set in CompareConfig
			if comparator.WhitelistChecker != nil {
				t.Error("WhitelistChecker should be nil")
			}
		})
	}
}

func TestCompareConfig_Integration(t *testing.T) {
	// Test integration: DefaultCompareConfig -> ToComparator
	t.Run("default config to comparator", func(t *testing.T) {
		config := DefaultCompareConfig()
		comparator := config.ToComparator()

		if !comparator.AllowPartialMatch {
			t.Error("Expected AllowPartialMatch to be true")
		}
		if !comparator.IgnoreAdditional {
			t.Error("Expected IgnoreAdditional to be true")
		}
		if comparator.DiffUnexpectedMask != diff.DefaultMask {
			t.Errorf("Expected DiffUnexpectedMask to be %d, got %d", diff.DefaultMask, comparator.DiffUnexpectedMask)
		}
	})

	// Test integration: ParseHexMask -> CompareConfig -> ToComparator
	t.Run("parse mask and create comparator", func(t *testing.T) {
		maskStr := "0x00001234"
		mask, err := ParseHexMask(maskStr)
		if err != nil {
			t.Fatalf("ParseHexMask failed: %v", err)
		}

		config := &CompareConfig{
			AllowPartialMatch:  false,
			IgnoreAdditional:   false,
			DiffUnexpectedMask: mask,
		}

		comparator := config.ToComparator()

		if comparator.DiffUnexpectedMask != 0x00001234 {
			t.Errorf("Expected DiffUnexpectedMask to be 0x00001234, got 0x%08X", comparator.DiffUnexpectedMask)
		}
	})
}

func BenchmarkDefaultCompareConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = DefaultCompareConfig()
	}
}

func BenchmarkParseHexMask(b *testing.B) {
	testCases := []string{
		"0x00000001",
		"0xFFFFFFFF",
		"0x12345678",
	}

	for _, tc := range testCases {
		b.Run(tc, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = ParseHexMask(tc)
			}
		})
	}
}

func BenchmarkToComparator(b *testing.B) {
	config := DefaultCompareConfig()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = config.ToComparator()
	}
}
