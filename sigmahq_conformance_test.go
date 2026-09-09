package sigma

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSigmaHQIngestedCorpusParsesCompletely(t *testing.T) {
	root := strings.TrimSpace(os.Getenv("SIGMAHQ_CORPUS_PATH"))
	if root == "" {
		t.Skip("set SIGMAHQ_CORPUS_PATH to a SigmaHQ/sigma checkout")
	}

	directories := []string{"rules", "rules-emerging-threats", "rules-threat-hunting", "rules-compliance"}
	parsed := 0
	for _, directory := range directories {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || (!strings.HasSuffix(path, ".yml") && !strings.HasSuffix(path, ".yaml")) {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if !strings.Contains(string(content), "detection:") {
				return nil
			}

			parsed++
			result := ExtractConditions(string(content))
			if len(result.Errors) != 0 {
				relativePath, _ := filepath.Rel(root, path)
				t.Errorf("%s: %s", relativePath, strings.Join(result.Errors, "; "))
			}
			if result.Expression == nil {
				relativePath, _ := filepath.Rel(root, path)
				t.Errorf("%s: parser produced no detection expression", relativePath)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", directory, err)
		}
	}
	if parsed == 0 {
		t.Fatal("SigmaHQ corpus contained no detection rules")
	}
	t.Logf("parsed %d/%d ingested SigmaHQ rules", parsed, parsed)
}
