package attacknetcli

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExportLokiRangePaginatesDeduplicatesAndSeals(t *testing.T) {
	requests := 0
	client := lokiDoer(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/loki/api/v1/status/buildinfo" {
			return lokiResponse(t, map[string]any{"version": "test"}), nil
		}
		requests++
		if request.URL.Query().Get("query") != `{attacknet_network="network"}` || request.URL.Query().Get("direction") != "forward" {
			t.Fatalf("unexpected Loki query: %s", request.URL.RawQuery)
		}
		values := [][]string{{"10", "first"}, {"11", "boundary"}}
		if requests == 2 {
			values = [][]string{{"11", "boundary"}, {"12", "last"}}
		}
		if requests == 3 {
			values = nil
		}
		return lokiResponse(t, map[string]any{"status": "success", "data": map[string]any{
			"resultType": "streams", "result": []any{map[string]any{"stream": map[string]string{"pod": "actor"}, "values": values}},
		}}), nil
	})
	output := filepath.Join(t.TempDir(), "loki")
	metadata, err := ExportLokiRange(context.Background(), client, LokiExportOptions{
		Endpoint: "http://loki.test", Network: "network", Start: time.Unix(0, 10), End: time.Unix(0, 20),
		OutputDirectory: output, PageLimit: 2, MaxPages: 4,
	}, func() time.Time { return time.Unix(20, 0).UTC() })
	if err != nil || !metadata.Complete || metadata.EntryCount != 3 || metadata.PageCount != 3 {
		t.Fatalf("unexpected complete export: %#v, %v", metadata, err)
	}
	file, err := os.Open(filepath.Join(output, "logs.jsonl.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(compressed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), "boundary") != 1 || !strings.Contains(string(raw), "first") || !strings.Contains(string(raw), "last") {
		t.Fatalf("unexpected JSONL: %s", raw)
	}
	if _, err := os.Stat(filepath.Join(output, "logs.jsonl.gz.partial")); !os.IsNotExist(err) {
		t.Fatal("successful export retained a partial artifact")
	}
}

func TestExportLokiRangeFailsClosedOnPaginationStall(t *testing.T) {
	client := lokiDoer(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/loki/api/v1/status/buildinfo" {
			return lokiResponse(t, map[string]any{"version": "test"}), nil
		}
		return lokiResponse(t, map[string]any{"status": "success", "data": map[string]any{
			"resultType": "streams", "result": []any{map[string]any{"stream": map[string]string{}, "values": [][]string{{"10", "same"}}}},
		}}), nil
	})
	output := filepath.Join(t.TempDir(), "loki")
	metadata, err := ExportLokiRange(context.Background(), client, LokiExportOptions{
		Endpoint: "http://loki.test", Network: "network", Start: time.Unix(0, 10), End: time.Unix(0, 20),
		OutputDirectory: output, PageLimit: 1, MaxPages: 3,
	}, time.Now)
	if err == nil || metadata.Complete || metadata.Failure == "" {
		t.Fatalf("pagination stall passed: %#v, %v", metadata, err)
	}
	if _, err := os.Stat(filepath.Join(output, "logs.jsonl.gz")); !os.IsNotExist(err) {
		t.Fatal("failed export published a final artifact")
	}
	raw, err := os.ReadFile(filepath.Join(output, "export.json"))
	if err != nil {
		t.Fatal(err)
	}
	var recorded LokiExportMetadata
	if json.Unmarshal(raw, &recorded) != nil || recorded.Complete {
		t.Fatalf("failure metadata is not truthful: %s", raw)
	}
}

func TestExportLokiRangePreservesIdenticalEntries(t *testing.T) {
	requests := 0
	client := lokiDoer(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/loki/api/v1/status/buildinfo" {
			return lokiResponse(t, map[string]any{"version": "test"}), nil
		}
		requests++
		values := [][]string{{"10", "duplicate"}, {"10", "duplicate"}, {"11", "boundary"}}
		if requests == 2 {
			values = [][]string{{"11", "boundary"}, {"12", "last"}}
		}
		return lokiResponse(t, map[string]any{"status": "success", "data": map[string]any{
			"resultType": "streams", "result": []any{map[string]any{"stream": map[string]string{"pod": "actor"}, "values": values}},
		}}), nil
	})
	output := filepath.Join(t.TempDir(), "loki")
	metadata, err := ExportLokiRange(context.Background(), client, LokiExportOptions{
		Endpoint: "http://loki.test", Network: "network", Start: time.Unix(0, 10), End: time.Unix(0, 20),
		OutputDirectory: output, PageLimit: 3, MaxPages: 3,
	}, time.Now)
	if err != nil || !metadata.Complete || metadata.EntryCount != 4 {
		t.Fatalf("duplicate-preserving export failed: %#v, %v", metadata, err)
	}
	file, err := os.Open(filepath.Join(output, "logs.jsonl.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(compressed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), `"line":"duplicate"`) != 2 || strings.Count(string(raw), `"line":"boundary"`) != 1 {
		t.Fatalf("legitimate duplicates were lost or boundary was repeated: %s", raw)
	}
}

func TestExportLokiRangeLeavesPartialWhenSourceChangesBeforeSeal(t *testing.T) {
	client := lokiDoer(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/loki/api/v1/status/buildinfo" {
			return lokiResponse(t, map[string]any{"version": "test"}), nil
		}
		return lokiResponse(t, map[string]any{"status": "success", "data": map[string]any{
			"resultType": "streams", "result": []any{},
		}}), nil
	})
	output := filepath.Join(t.TempDir(), "loki")
	metadata, err := ExportLokiRange(context.Background(), client, LokiExportOptions{
		Endpoint: "http://loki.test", Network: "network", Start: time.Unix(0, 10), End: time.Unix(0, 20),
		OutputDirectory: output, VerifyBeforeSeal: func() error {
			return errors.New("Loki source identity changed during export")
		},
	}, time.Now)
	if err == nil || metadata.Complete || !strings.Contains(metadata.Failure, "source identity changed") {
		t.Fatalf("source replacement was sealed as complete: %#v, %v", metadata, err)
	}
	if _, err := os.Stat(filepath.Join(output, "logs.jsonl.gz")); !os.IsNotExist(err) {
		t.Fatal("source replacement published a final log artifact")
	}
	if _, err := os.Stat(filepath.Join(output, "logs.jsonl.gz.partial")); err != nil {
		t.Fatalf("source replacement did not retain a partial artifact: %v", err)
	}
}

func TestBoundedJSONRejectsOversizeAndTrailingDocuments(t *testing.T) {
	for name, input := range map[string]string{
		"oversize": `{"value":"too-large"}`,
		"trailing": `{} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			maximum := int64(len(input))
			if name == "oversize" {
				maximum--
			}
			var target map[string]any
			if err := decodeBoundedJSON(strings.NewReader(input), &target, maximum); err == nil {
				t.Fatalf("%s JSON passed its fail-closed decoder", name)
			}
		})
	}
}

type lokiDoer func(*http.Request) (*http.Response, error)

func (do lokiDoer) Do(request *http.Request) (*http.Response, error) { return do(request) }

func lokiResponse(t *testing.T, value any) *http.Response {
	t.Helper()
	buffer := &strings.Builder{}
	if err := json.NewEncoder(buffer).Encode(value); err != nil {
		t.Fatal(err)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(buffer.String()))}
}
