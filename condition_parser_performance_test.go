package sigma

import "testing"

func BenchmarkMatchDetectionItems(b *testing.B) {
	items := map[string]*detectionItem{
		"selection_process":  {},
		"selection_network":  {},
		"selection_file":     {},
		"selection_registry": {},
		"filter_process":     {},
		"filter_network":     {},
		"other":              {},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = matchDetectionItems("selection_*", items)
	}
}
