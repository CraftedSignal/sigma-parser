package sigma

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCorpus runs the parser against all .yml files in testdata/corpus/.
// Download real SigmaHQ rules into that directory:
//
//	git clone --depth 1 https://github.com/SigmaHQ/sigma.git /tmp/sigma
//	cp /tmp/sigma/rules/windows/**/*.yml testdata/corpus/
//
// Or use: make scrape-corpus
func TestCorpus(t *testing.T) {
	corpusDir := "testdata/corpus"

	if _, err := os.ReadDir(corpusDir); err != nil {
		t.Skipf("corpus directory not found: %v (run 'make scrape-corpus' to populate)", err)
		return
	}

	ymlFiles := make([]string, 0)
	err := filepath.Walk(corpusDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			ymlFiles = append(ymlFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking corpus: %v", err)
	}

	if len(ymlFiles) == 0 {
		t.Skip("no .yml files found in corpus directory")
		return
	}

	t.Logf("Testing %d corpus files", len(ymlFiles))

	var (
		totalFiles   int
		successFiles int
		errorFiles   int
		panicFiles   int
	)

	for _, path := range ymlFiles {
		totalFiles++
		relPath, _ := filepath.Rel(corpusDir, path)

		t.Run(relPath, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}

			content := string(data)

			// Skip non-Sigma YAML files (configs, etc.)
			if !strings.Contains(content, "detection:") {
				t.Skip("not a Sigma rule (no detection block)")
				return
			}

			// The parser must NEVER panic
			result := ExtractConditions(content)

			if result == nil {
				panicFiles++
				t.Fatal("ExtractConditions returned nil")
			}

			if result.ComputedFields == nil {
				t.Error("ComputedFields should never be nil")
			}

			// Check for timeout errors (indicates pathological input)
			for _, e := range result.Errors {
				if strings.Contains(e, "timed out") {
					t.Errorf("parser timed out on %s", relPath)
				}
				if strings.Contains(e, "panic") {
					panicFiles++
					t.Errorf("parser panicked on %s: %s", relPath, e)
				}
			}

			if len(result.Errors) > 0 {
				errorFiles++
				// Log but don't fail — some rules may use unsupported features
				t.Logf("parse warnings for %s: %v", relPath, result.Errors)
			} else {
				successFiles++
			}

			// Basic sanity: if no errors, should have at least 1 condition (unless aggregation-only)
			if len(result.Errors) == 0 && len(result.Conditions) == 0 && len(result.Commands) == 0 {
				t.Logf("warning: no conditions and no commands for %s", relPath)
			}
		})
	}

	t.Logf("Corpus results: %d total, %d success, %d with warnings, %d panics",
		totalFiles, successFiles, errorFiles, panicFiles)

	if panicFiles > 0 {
		t.Errorf("%d files caused panics", panicFiles)
	}
}

// TestCorpus_NoPanics is a simplified version that only checks for panics,
// useful for quick validation of the entire corpus.
func TestCorpus_NoPanics(t *testing.T) {
	corpusDir := "testdata/corpus"

	var ymlFiles []string
	err := filepath.Walk(corpusDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable files
		}
		if !info.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			ymlFiles = append(ymlFiles, path)
		}
		return nil
	})
	if err != nil || len(ymlFiles) == 0 {
		t.Skip("no corpus files found")
		return
	}

	panics := 0
	for _, path := range ymlFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		result := ExtractConditions(string(data))
		if result == nil {
			panics++
			t.Errorf("nil result for %s", path)
		}
		for _, e := range result.Errors {
			if strings.Contains(e, "panic") {
				panics++
				t.Errorf("panic in %s: %s", path, e)
			}
		}
	}

	t.Logf("Tested %d files, %d panics", len(ymlFiles), panics)
}
