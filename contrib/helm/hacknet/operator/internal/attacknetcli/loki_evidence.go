package attacknetcli

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	lokiExportSchema     = "stacks-attacknet-loki-export/v1"
	defaultLokiPageLimit = 5000
	defaultLokiMaxPages  = 1000
	maximumLokiBodyBytes = 32 << 20
)

var networkLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)

// LokiHTTPClient is the bounded HTTP boundary used by the retained-log exporter.
type LokiHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// LokiExportOptions defines one complete retained-log export.
type LokiExportOptions struct {
	Endpoint        string
	Network         string
	Start           time.Time
	End             time.Time
	OutputDirectory string
	PageLimit       int
	MaxPages        int
	// VerifyBeforeSeal runs after the compressed stream is closed and before
	// the partial artifact is promoted to the final evidence path.
	VerifyBeforeSeal func() error
}

// LokiExportMetadata is the independently verifiable export result.
type LokiExportMetadata struct {
	SchemaVersion     string         `json:"schemaVersion"`
	Complete          bool           `json:"complete"`
	Selector          string         `json:"selector"`
	StartNS           string         `json:"startNs"`
	EndNS             string         `json:"endNs"`
	Direction         string         `json:"direction"`
	PageLimit         int            `json:"pageLimit"`
	PageCount         int            `json:"pageCount"`
	EntryCount        int            `json:"entryCount"`
	Failure           string         `json:"failure,omitempty"`
	Pages             []LokiPage     `json:"pages"`
	BuildInfo         map[string]any `json:"buildInfo,omitempty"`
	LogArtifact       string         `json:"logArtifact,omitempty"`
	PartialArtifact   string         `json:"partialLogArtifact,omitempty"`
	Compression       string         `json:"compression"`
	UncompressedBytes int64          `json:"uncompressedBytes"`
	CompressedBytes   int64          `json:"compressedBytes"`
	ExportedAt        time.Time      `json:"exportedAt"`
}

// LokiPage records one bounded pagination step.
type LokiPage struct {
	Page               int    `json:"page"`
	StartNS            string `json:"startNs"`
	RawEntries         int    `json:"rawEntries"`
	NewEntries         int    `json:"newEntries"`
	MaximumTimestampNS string `json:"maximumTimestampNs,omitempty"`
}

type lokiEntry struct {
	TimestampNS string            `json:"timestampNs"`
	Labels      map[string]string `json:"labels"`
	Line        string            `json:"line"`
}

type lokiQueryResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Stream map[string]string `json:"stream"`
			Values [][]string        `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

// ExportLokiRange writes complete forward-paginated Loki logs as compressed
// JSONL. An incomplete export retains its partial artifact and returns an error.
func ExportLokiRange(ctx context.Context, client LokiHTTPClient, options LokiExportOptions, now func() time.Time) (metadata LokiExportMetadata, returnedErr error) {
	if err := validateLokiOptions(client, options); err != nil {
		return metadata, err
	}
	if now == nil {
		now = time.Now
	}
	if options.PageLimit == 0 {
		options.PageLimit = defaultLokiPageLimit
	}
	if options.MaxPages == 0 {
		options.MaxPages = defaultLokiMaxPages
	}
	if err := os.MkdirAll(options.OutputDirectory, 0o700); err != nil {
		return metadata, fmt.Errorf("create Loki evidence directory: %w", err)
	}
	partialPath := filepath.Join(options.OutputDirectory, "logs.jsonl.gz.partial")
	finalPath := filepath.Join(options.OutputDirectory, "logs.jsonl.gz")
	if _, err := os.Stat(finalPath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return metadata, errors.New("refusing to overwrite existing Loki export")
	}
	file, err := os.OpenFile(partialPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return metadata, fmt.Errorf("create partial Loki artifact: %w", err)
	}
	gzipWriter := gzip.NewWriter(file)
	buffered := bufio.NewWriter(gzipWriter)
	metadata = LokiExportMetadata{
		SchemaVersion: lokiExportSchema, Selector: fmt.Sprintf(`{attacknet_network=%q}`, options.Network),
		StartNS: strconv.FormatInt(options.Start.UnixNano(), 10), EndNS: strconv.FormatInt(options.End.UnixNano(), 10),
		Direction: "forward", PageLimit: options.PageLimit, Compression: "gzip", PartialArtifact: "logs.jsonl.gz.partial",
	}
	defer func() {
		flushErr := buffered.Flush()
		closeGzipErr := gzipWriter.Close()
		closeErr := file.Close()
		if returnedErr == nil {
			returnedErr = errors.Join(flushErr, closeGzipErr, closeErr)
		}
		if info, statErr := os.Stat(partialPath); statErr == nil {
			metadata.CompressedBytes = info.Size()
		}
		metadata.ExportedAt = now().UTC()
		if returnedErr == nil && metadata.Complete && options.VerifyBeforeSeal != nil {
			if verifyErr := options.VerifyBeforeSeal(); verifyErr != nil {
				returnedErr = verifyErr
				metadata.Complete = false
				metadata.Failure = verifyErr.Error()
			}
		}
		if returnedErr == nil && metadata.Complete {
			metadata.PartialArtifact = ""
			metadata.LogArtifact = "logs.jsonl.gz"
			if renameErr := os.Rename(partialPath, finalPath); renameErr != nil {
				returnedErr = renameErr
				metadata.Complete = false
				metadata.Failure = renameErr.Error()
			}
		} else {
			metadata.Complete = false
			if metadata.Failure == "" && returnedErr != nil {
				metadata.Failure = returnedErr.Error()
			}
		}
		if writeErr := writePrivateJSON(filepath.Join(options.OutputDirectory, "export.json"), metadata); returnedErr == nil && writeErr != nil {
			returnedErr = writeErr
		}
	}()

	buildInfo := map[string]any{}
	if err := lokiJSON(ctx, client, options.Endpoint+"/loki/api/v1/status/buildinfo", &buildInfo); err != nil {
		return metadata, fmt.Errorf("query Loki build info: %w", err)
	}
	metadata.BuildInfo = buildInfo
	cursor := options.Start.UnixNano()
	end := options.End.UnixNano()
	boundarySeen := map[string]int{}
	for page := 1; page <= options.MaxPages; page++ {
		entries, rawCount, err := queryLokiPage(ctx, client, options, cursor, end)
		if err != nil {
			return metadata, err
		}
		fresh := make([]lokiEntry, 0, len(entries))
		boundaryOccurrences := map[string]int{}
		for _, entry := range entries {
			key := lokiEntryKey(entry)
			if mustInt64(entry.TimestampNS) == cursor {
				boundaryOccurrences[key]++
				if boundaryOccurrences[key] <= boundarySeen[key] {
					continue
				}
			}
			fresh = append(fresh, entry)
		}
		for _, entry := range fresh {
			line, marshalErr := json.Marshal(entry)
			if marshalErr != nil {
				return metadata, marshalErr
			}
			line = append(line, '\n')
			written, writeErr := buffered.Write(line)
			metadata.UncompressedBytes += int64(written)
			if writeErr != nil {
				return metadata, writeErr
			}
		}
		metadata.EntryCount += len(fresh)
		maximum := int64(-1)
		if len(entries) > 0 {
			maximum = mustInt64(entries[len(entries)-1].TimestampNS)
		}
		pageResult := LokiPage{Page: page, StartNS: strconv.FormatInt(cursor, 10), RawEntries: rawCount, NewEntries: len(fresh)}
		if maximum >= 0 {
			pageResult.MaximumTimestampNS = strconv.FormatInt(maximum, 10)
		}
		metadata.Pages = append(metadata.Pages, pageResult)
		metadata.PageCount = len(metadata.Pages)
		if rawCount < options.PageLimit {
			metadata.Complete = true
			return metadata, nil
		}
		if maximum < cursor || len(fresh) == 0 {
			metadata.Failure = "pagination made no progress; more than one page may share a timestamp"
			return metadata, errors.New(metadata.Failure)
		}
		nextBoundary := map[string]int{}
		if maximum == cursor {
			for key, count := range boundarySeen {
				nextBoundary[key] = count
			}
		}
		maximumOccurrences := map[string]int{}
		for _, entry := range entries {
			if mustInt64(entry.TimestampNS) == maximum {
				key := lokiEntryKey(entry)
				maximumOccurrences[key]++
				if maximumOccurrences[key] > nextBoundary[key] {
					nextBoundary[key] = maximumOccurrences[key]
				}
			}
		}
		boundarySeen, cursor = nextBoundary, maximum
	}
	metadata.Failure = fmt.Sprintf("pagination exceeded maxPages=%d", options.MaxPages)
	return metadata, errors.New(metadata.Failure)
}

func validateLokiOptions(client LokiHTTPClient, options LokiExportOptions) error {
	if client == nil {
		return errors.New("Loki HTTP client is required")
	}
	endpoint, err := url.Parse(options.Endpoint)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" || endpoint.Path != "" {
		return errors.New("Loki endpoint must be an HTTP origin")
	}
	if !networkLabelPattern.MatchString(options.Network) {
		return errors.New("network must be a bounded DNS label")
	}
	if options.Start.IsZero() || options.End.IsZero() || options.Start.After(options.End) {
		return errors.New("Loki export requires an ordered non-zero interval")
	}
	if options.OutputDirectory == "" {
		return errors.New("Loki output directory is required")
	}
	if options.PageLimit < 0 || options.PageLimit > defaultLokiPageLimit || options.MaxPages < 0 || options.MaxPages > 10000 {
		return errors.New("Loki pagination bounds are invalid")
	}
	return nil
}

func queryLokiPage(ctx context.Context, client LokiHTTPClient, options LokiExportOptions, start, end int64) ([]lokiEntry, int, error) {
	endpoint, _ := url.Parse(options.Endpoint + "/loki/api/v1/query_range")
	query := endpoint.Query()
	query.Set("query", fmt.Sprintf(`{attacknet_network=%q}`, options.Network))
	query.Set("start", strconv.FormatInt(start, 10))
	query.Set("end", strconv.FormatInt(end, 10))
	query.Set("direction", "forward")
	query.Set("limit", strconv.Itoa(options.PageLimit))
	endpoint.RawQuery = query.Encode()
	response := lokiQueryResponse{}
	if err := lokiJSON(ctx, client, endpoint.String(), &response); err != nil {
		return nil, 0, err
	}
	if response.Status != "success" || response.Data.ResultType != "streams" {
		return nil, 0, errors.New("Loki returned an unexpected query response")
	}
	entries := []lokiEntry{}
	for _, stream := range response.Data.Result {
		for _, value := range stream.Values {
			if len(value) != 2 {
				return nil, 0, errors.New("Loki stream entry must contain a timestamp and line")
			}
			if _, err := strconv.ParseInt(value[0], 10, 64); err != nil {
				return nil, 0, errors.New("Loki stream timestamp is invalid")
			}
			entries = append(entries, lokiEntry{TimestampNS: value[0], Labels: stream.Stream, Line: value[1]})
		}
	}
	sort.Slice(entries, func(left, right int) bool {
		leftTime, rightTime := mustInt64(entries[left].TimestampNS), mustInt64(entries[right].TimestampNS)
		if leftTime != rightTime {
			return leftTime < rightTime
		}
		leftLabels, _ := json.Marshal(entries[left].Labels)
		rightLabels, _ := json.Marshal(entries[right].Labels)
		if compared := strings.Compare(string(leftLabels), string(rightLabels)); compared != 0 {
			return compared < 0
		}
		return entries[left].Line < entries[right].Line
	})
	return entries, len(entries), nil
}

func lokiJSON(ctx context.Context, client LokiHTTPClient, endpoint string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Loki query failed with HTTP %d", response.StatusCode)
	}
	if err := decodeBoundedJSON(response.Body, target, maximumLokiBodyBytes); err != nil {
		return fmt.Errorf("decode Loki response: %w", err)
	}
	return nil
}

func decodeBoundedJSON(reader io.Reader, target any, maximum int64) error {
	if reader == nil || maximum <= 0 {
		return errors.New("JSON reader and positive byte bound are required")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return fmt.Errorf("read JSON response: %w", err)
	}
	if int64(len(raw)) > maximum {
		return fmt.Errorf("JSON response exceeds %d bytes", maximum)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return err
	}
	return nil
}

func lokiEntryKey(entry lokiEntry) string {
	raw, _ := json.Marshal(entry)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func mustInt64(value string) int64 {
	result, _ := strconv.ParseInt(value, 10, 64)
	return result
}

func writePrivateJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	temporary := path + ".partial"
	if err := os.WriteFile(temporary, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
