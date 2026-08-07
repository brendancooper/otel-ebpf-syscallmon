package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func writeProcComm(t *testing.T, root, pid, comm string) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverMatchingProcesses(t *testing.T) {
	procRoot := t.TempDir()
	writeProcComm(t, procRoot, "101", "worker")
	writeProcComm(t, procRoot, "102", "other")
	writeProcComm(t, procRoot, "103", "worker") // monitor PID: excluded
	if err := os.Mkdir(filepath.Join(procRoot, "not-a-pid"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(procRoot, "104"), 0o755); err != nil {
		t.Fatal(err) // missing comm simulates a process exiting during the scan
	}

	got, err := discoverMatchingProcesses(procRoot, map[string]struct{}{"worker": {}}, 103)
	if err != nil {
		t.Fatalf("discoverMatchingProcesses() error = %v", err)
	}
	want := map[uint32]string{101: "worker"}
	if len(got) != len(want) || got[101] != "worker" {
		t.Fatalf("discoverMatchingProcesses() = %#v, want %#v", got, want)
	}
}

func TestAppendMissingProcessZeros(t *testing.T) {
	entries := []MetricEntry{{PID: 101, Comm: "worker", ID: scRead, Name: "read", Count: 3}}
	matching := map[uint32]string{101: "worker", 102: "worker", 103: "worker"}
	active := map[uint32]struct{}{101: {}}

	got := appendMissingProcessZeros(entries, matching, active)
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3: %#v", len(got), got)
	}
	for _, entry := range got[1:] {
		if !entry.SyntheticZero || entry.Count != 0 || entry.Name != syntheticCallName || entry.Comm != "worker" {
			t.Fatalf("unexpected synthetic entry: %#v", entry)
		}
	}
	if got[1].PID != 102 || got[2].PID != 103 {
		t.Fatalf("synthetic entries are not PID sorted: %#v", got[1:])
	}
}

func TestExportOTLPJSONSyntheticZero(t *testing.T) {
	var payload otlpEnvelope
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	entries := []MetricEntry{
		{PID: 101, Comm: "worker", ID: scRead, Name: "read", Count: 3, AvgMs: 1.5, MaxMs: 2.5},
		{PID: 102, Comm: "worker", SyntheticZero: true},
	}
	if err := exportOTLPJSON(t.Context(), server.URL, entries, false); err != nil {
		t.Fatalf("exportOTLPJSON() error = %v", err)
	}

	metrics := payload.ResourceMetrics[0].ScopeMetrics[0].Metrics
	byName := make(map[string]otlpMetric, len(metrics))
	for _, metric := range metrics {
		byName[metric.Name] = metric
	}
	countMetric, ok := byName["syscall_count"]
	if !ok || len(countMetric.Gauge.DataPoints) != 2 {
		t.Fatalf("syscall_count = %#v, want two datapoints", countMetric)
	}
	for _, name := range []string{"syscall_avg_ms", "syscall_max_ms"} {
		metric, ok := byName[name]
		if !ok {
			t.Fatalf("normal entry did not export %s", name)
		}
		for _, dp := range metric.Gauge.DataPoints {
			for _, attr := range dp.Attributes {
				if attr.Key == "pid" && attr.Value.IntValue != nil && *attr.Value.IntValue == 102 {
					t.Fatalf("synthetic zero unexpectedly exported %s: %#v", name, metric)
				}
			}
		}
	}

	var zeroDP *otlpGaugeDP
	for i := range countMetric.Gauge.DataPoints {
		dp := &countMetric.Gauge.DataPoints[i]
		for _, attr := range dp.Attributes {
			if attr.Key == "pid" && attr.Value.IntValue != nil && *attr.Value.IntValue == 102 {
				zeroDP = dp
			}
		}
	}
	if zeroDP == nil || zeroDP.AsInt == nil || *zeroDP.AsInt != 0 {
		t.Fatalf("missing zero syscall_count datapoint: %#v", countMetric.Gauge.DataPoints)
	}
	var call string
	for _, attr := range zeroDP.Attributes {
		if attr.Key == "call" && attr.Value.StringValue != nil {
			call = *attr.Value.StringValue
		}
	}
	if call != syntheticCallName {
		t.Fatalf("synthetic zero call = %q, want %q; attrs=%#v", call, syntheticCallName, zeroDP.Attributes)
	}
}
