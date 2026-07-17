package agent

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const probeSpoolSchemaVersion = 1

// ProbeSpoolLimits centralizes every on-disk backlog bound. Callers may lower
// these values in tests, but production uses DefaultProbeSpoolLimits.
type ProbeSpoolLimits struct {
	TTL                time.Duration
	MaxPendingItems    int
	MaxPendingBytes    int64
	MaxItemBytes       int64
	MinFreeBytes       uint64
	MaxQuarantineItems int
	MaxQuarantineBytes int64
}

func DefaultProbeSpoolLimits() ProbeSpoolLimits {
	return ProbeSpoolLimits{
		TTL:                72 * time.Hour,
		MaxPendingItems:    16384,
		MaxPendingBytes:    256 << 20,
		MaxItemBytes:       1 << 20,
		MinFreeBytes:       512 << 20,
		MaxQuarantineItems: 128,
		MaxQuarantineBytes: 16 << 20,
	}
}

type ProbeSpoolOptions struct {
	Limits    ProbeSpoolLimits
	Now       func() time.Time
	FreeBytes func(string) (uint64, error)
	Random    io.Reader
	// AtomicWrite is a test hook for filesystem failures such as ENOSPC.
	// Production callers leave it nil.
	AtomicWrite func(string, []byte) error
}

type ProbeSpool struct {
	mu            sync.Mutex
	root          string
	pendingDir    string
	quarantineDir string
	limits        ProbeSpoolLimits
	now           func() time.Time
	freeBytes     func(string) (uint64, error)
	random        io.Reader
	atomicWrite   func(string, []byte) error
	notify        chan struct{}
}

type ProbeSpoolItem struct {
	ID      string
	Body    []byte
	Created time.Time
	Attempt uint32
	NextAt  time.Time
}

type probeSpoolEnvelope struct {
	SchemaVersion int             `json:"schema_version"`
	Created       int64           `json:"created"`
	Attempt       uint32          `json:"attempt"`
	NextAt        int64           `json:"next_at"`
	Checksum      string          `json:"checksum"`
	Batch         json.RawMessage `json:"batch"`
}

func NewProbeSpool(dataDir string, options ProbeSpoolOptions) (*ProbeSpool, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, fmt.Errorf("probe spool data directory is required")
	}
	if !filepath.IsAbs(dataDir) {
		return nil, fmt.Errorf("probe spool data directory must be absolute")
	}
	limits := options.Limits
	if limits == (ProbeSpoolLimits{}) {
		limits = DefaultProbeSpoolLimits()
	}
	if err := validateProbeSpoolLimits(limits); err != nil {
		return nil, err
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	freeBytes := options.FreeBytes
	if freeBytes == nil {
		freeBytes = diskFreeBytes
	}
	randomSource := options.Random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	root := filepath.Join(filepath.Clean(dataDir), "probe-spool")
	spool := &ProbeSpool{
		root:          root,
		pendingDir:    filepath.Join(root, "pending"),
		quarantineDir: filepath.Join(root, "quarantine"),
		limits:        limits,
		now:           now,
		freeBytes:     freeBytes,
		random:        randomSource,
		atomicWrite:   options.AtomicWrite,
		notify:        make(chan struct{}, 1),
	}
	if spool.atomicWrite == nil {
		spool.atomicWrite = atomicWritePrivateFile
	}
	for _, path := range []string{filepath.Clean(dataDir), root, spool.pendingDir, spool.quarantineDir} {
		if err := ensurePrivateDirectory(path); err != nil {
			return nil, fmt.Errorf("prepare probe spool directory: %w", err)
		}
	}
	return spool, nil
}

func validateProbeSpoolLimits(limits ProbeSpoolLimits) error {
	if limits.TTL <= 0 || limits.MaxPendingItems <= 0 || limits.MaxPendingBytes <= 0 || limits.MaxItemBytes <= 0 ||
		limits.MaxQuarantineItems <= 0 || limits.MaxQuarantineBytes <= 0 {
		return fmt.Errorf("invalid probe spool limits")
	}
	if limits.MaxItemBytes > limits.MaxPendingBytes {
		return fmt.Errorf("probe spool item limit exceeds pending byte limit")
	}
	return nil
}

func (s *ProbeSpool) Enqueue(rounds []ProbeRound) (string, error) {
	body, err := marshalProbeResults(rounds)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now().UTC()
	if err := s.cleanupPendingLocked(now); err != nil {
		return "", err
	}
	envelope := probeSpoolEnvelope{
		SchemaVersion: probeSpoolSchemaVersion,
		Created:       now.UnixNano(),
		NextAt:        now.UnixNano(),
		Checksum:      probeSpoolChecksum(body),
		Batch:         body,
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	if int64(len(encoded)) > s.limits.MaxItemBytes {
		return "", fmt.Errorf("probe spool item exceeds %d bytes", s.limits.MaxItemBytes)
	}
	count, totalBytes, err := s.pendingUsageLocked()
	if err != nil {
		return "", err
	}
	if count >= s.limits.MaxPendingItems || totalBytes+int64(len(encoded)) > s.limits.MaxPendingBytes {
		return "", fmt.Errorf("probe spool capacity exceeded (items=%d bytes=%d)", count, totalBytes)
	}
	free, err := s.freeBytes(s.root)
	if err != nil {
		return "", fmt.Errorf("check probe spool free space: %w", err)
	}
	if free < s.limits.MinFreeBytes+uint64(len(encoded)) {
		return "", fmt.Errorf("probe spool free space below minimum")
	}
	id, err := s.newIDLocked(now)
	if err != nil {
		return "", err
	}
	path := filepath.Join(s.pendingDir, id+".json")
	if err := s.atomicWrite(path, encoded); err != nil {
		return "", fmt.Errorf("persist probe spool item: %w", err)
	}
	s.signal()
	return id, nil
}

func marshalProbeResults(rounds []ProbeRound) ([]byte, error) {
	if len(rounds) == 0 {
		return nil, fmt.Errorf("probe spool batch is empty")
	}
	configVersion, err := commonProbeConfigVersion(rounds)
	if err != nil {
		return nil, err
	}
	payload := ProbeResultsRequest{ConfigVersion: configVersion, Rounds: make([]probeRoundPayload, 0, len(rounds))}
	for _, round := range rounds {
		payload.Rounds = append(payload.Rounds, probeRoundPayload{
			RoundID: round.RoundID, TargetID: round.TargetID, TS: round.TS.UTC().Unix(), Type: round.Type, Samples: round.Samples,
		})
	}
	return json.Marshal(payload)
}

func (s *ProbeSpool) Next(now time.Time) (*ProbeSpoolItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.cleanupPendingLocked(now.UTC()); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.pendingDir)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.pendingDir, entry.Name())
		envelope, _, err := s.readEnvelopeLocked(path)
		if err != nil {
			if quarantineErr := s.quarantinePathLocked(path, "invalid"); quarantineErr != nil {
				return nil, fmt.Errorf("quarantine invalid probe spool item: %w", quarantineErr)
			}
			continue
		}
		created := time.Unix(0, envelope.Created).UTC()
		if now.UTC().Sub(created) >= s.limits.TTL {
			if err := removeFileAndSync(path); err != nil {
				return nil, err
			}
			continue
		}
		nextAt := time.Unix(0, envelope.NextAt).UTC()
		if nextAt.After(now.UTC()) {
			continue
		}
		return probeSpoolItemFromEnvelope(strings.TrimSuffix(entry.Name(), ".json"), envelope), nil
	}
	return nil, nil
}

// Load returns a validated copy of a pending item, including its durable retry
// metadata. It does not apply the due-time or TTL filters used by Next.
func (s *ProbeSpool) Load(id string) (*ProbeSpoolItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := s.pendingPathLocked(id)
	if err != nil {
		return nil, err
	}
	envelope, _, err := s.readEnvelopeLocked(path)
	if err != nil {
		return nil, err
	}
	return probeSpoolItemFromEnvelope(id, envelope), nil
}

// ScheduleRetry atomically persists the attempt counter and retry gate before
// UploadOne reports the retryable failure to its caller.
func (s *ProbeSpool) ScheduleRetry(id string, attempt uint32, nextAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := s.pendingPathLocked(id)
	if err != nil {
		return err
	}
	envelope, _, err := s.readEnvelopeLocked(path)
	if err != nil {
		return err
	}
	if nextAt.IsZero() {
		return fmt.Errorf("probe spool retry time is required")
	}
	envelope.Attempt = attempt
	envelope.NextAt = nextAt.UTC().UnixNano()
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	if int64(len(encoded)) > s.limits.MaxItemBytes {
		return fmt.Errorf("probe spool item exceeds %d bytes", s.limits.MaxItemBytes)
	}
	if err := s.atomicWrite(path, encoded); err != nil {
		return fmt.Errorf("persist probe spool retry metadata: %w", err)
	}
	s.signal()
	return nil
}

// Ack permanently removes a successfully accepted item. Callers must invoke
// this only after a 2xx response from the Controller.
func (s *ProbeSpool) Ack(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := s.pendingPathLocked(id)
	if err != nil {
		return err
	}
	return removeFileAndSync(path)
}

// Quarantine removes a terminal or malformed item from the upload queue while
// retaining its exact bytes in the bounded quarantine directory.
func (s *ProbeSpool) Quarantine(id, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, err := s.pendingPathLocked(id)
	if err != nil {
		return err
	}
	return s.quarantinePathLocked(path, reason)
}

func (s *ProbeSpool) pendingPathLocked(id string) (string, error) {
	if id == "" || id == "." || id == ".." || filepath.Base(id) != id ||
		strings.ContainsAny(id, `/\\`) || strings.HasSuffix(strings.ToLower(id), ".json") {
		return "", fmt.Errorf("invalid probe spool item id")
	}
	return filepath.Join(s.pendingDir, id+".json"), nil
}

func probeSpoolItemFromEnvelope(id string, envelope probeSpoolEnvelope) *ProbeSpoolItem {
	return &ProbeSpoolItem{
		ID:      id,
		Body:    append([]byte(nil), envelope.Batch...),
		Created: time.Unix(0, envelope.Created).UTC(),
		Attempt: envelope.Attempt,
		NextAt:  time.Unix(0, envelope.NextAt).UTC(),
	}
}

func (s *ProbeSpool) cleanupPendingLocked(now time.Time) error {
	entries, err := os.ReadDir(s.pendingDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(s.pendingDir, entry.Name())
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			if err := s.quarantinePathLocked(path, "unexpected"); err != nil {
				return err
			}
			continue
		}
		envelope, _, readErr := s.readEnvelopeLocked(path)
		if readErr != nil {
			if err := s.quarantinePathLocked(path, "invalid"); err != nil {
				return err
			}
			continue
		}
		if now.Sub(time.Unix(0, envelope.Created).UTC()) >= s.limits.TTL {
			if err := removeFileAndSync(path); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *ProbeSpool) readEnvelopeLocked(path string) (probeSpoolEnvelope, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return probeSpoolEnvelope{}, 0, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return probeSpoolEnvelope{}, info.Size(), fmt.Errorf("spool item is not a regular file")
	}
	if info.Size() > s.limits.MaxItemBytes {
		return probeSpoolEnvelope{}, info.Size(), fmt.Errorf("spool item is too large")
	}
	file, err := os.Open(path)
	if err != nil {
		return probeSpoolEnvelope{}, info.Size(), err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, s.limits.MaxItemBytes+1))
	if err != nil {
		return probeSpoolEnvelope{}, info.Size(), err
	}
	if int64(len(content)) > s.limits.MaxItemBytes {
		return probeSpoolEnvelope{}, info.Size(), fmt.Errorf("spool item is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var envelope probeSpoolEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return probeSpoolEnvelope{}, info.Size(), err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return probeSpoolEnvelope{}, info.Size(), fmt.Errorf("spool item has trailing data")
	}
	if envelope.SchemaVersion != probeSpoolSchemaVersion || envelope.Created <= 0 || envelope.NextAt <= 0 || len(envelope.Batch) == 0 {
		return probeSpoolEnvelope{}, info.Size(), fmt.Errorf("invalid probe spool envelope")
	}
	if !strings.EqualFold(envelope.Checksum, probeSpoolChecksum(envelope.Batch)) {
		return probeSpoolEnvelope{}, info.Size(), fmt.Errorf("probe spool checksum mismatch")
	}
	var payload ProbeResultsRequest
	if err := json.Unmarshal(envelope.Batch, &payload); err != nil || len(payload.Rounds) == 0 {
		return probeSpoolEnvelope{}, info.Size(), fmt.Errorf("invalid probe spool batch")
	}
	return envelope, info.Size(), nil
}

func (s *ProbeSpool) pendingUsageLocked() (int, int64, error) {
	entries, err := os.ReadDir(s.pendingDir)
	if err != nil {
		return 0, 0, err
	}
	var count int
	var total int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return 0, 0, err
		}
		count++
		total += info.Size()
	}
	return count, total, nil
}

func (s *ProbeSpool) newIDLocked(now time.Time) (string, error) {
	var randomBytes [16]byte
	if _, err := io.ReadFull(s.random, randomBytes[:]); err != nil {
		return "", fmt.Errorf("generate probe spool id: %w", err)
	}
	return fmt.Sprintf("%020d-%s", now.UnixNano(), hex.EncodeToString(randomBytes[:])), nil
}

func probeSpoolChecksum(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func atomicWritePrivateFile(path string, content []byte) error {
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, ".probe-spool-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	keep := false
	defer func() {
		_ = temp.Close()
		if !keep {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temp.Write(content); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := replaceFileAtomically(tempPath, path); err != nil {
		return err
	}
	keep = true
	return syncDirectory(directory)
}

func removeFileAndSync(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func (s *ProbeSpool) quarantinePathLocked(path, reason string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		// Never rename and chmod a symlink: chmod would follow its target. The
		// pending directory is private agent state, so unexpected filesystem
		// objects are safely removed rather than retained as evidence.
		if err := os.RemoveAll(path); err != nil {
			return err
		}
		return syncDirectory(s.pendingDir)
	}
	if info.Size() > s.limits.MaxQuarantineBytes {
		return removeFileAndSync(path)
	}
	if err := s.pruneQuarantineLocked(info.Size()); err != nil {
		return err
	}
	name := filepath.Base(path)
	reason = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, strings.ToLower(reason))
	destination := filepath.Join(s.quarantineDir, name+"."+reason)
	if err := os.Rename(path, destination); err != nil {
		return err
	}
	if err := os.Chmod(destination, 0o600); err != nil {
		return err
	}
	if err := syncDirectory(s.pendingDir); err != nil {
		return err
	}
	return syncDirectory(s.quarantineDir)
}

func (s *ProbeSpool) pruneQuarantineLocked(incomingBytes int64) error {
	entries, err := os.ReadDir(s.quarantineDir)
	if err != nil {
		return err
	}
	type quarantineEntry struct {
		name string
		size int64
	}
	items := make([]quarantineEntry, 0, len(entries))
	var total int64
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		items = append(items, quarantineEntry{name: entry.Name(), size: info.Size()})
		total += info.Size()
	}
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	for len(items)+1 > s.limits.MaxQuarantineItems || total+incomingBytes > s.limits.MaxQuarantineBytes {
		if len(items) == 0 {
			break
		}
		oldest := items[0]
		if err := os.Remove(filepath.Join(s.quarantineDir, oldest.name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		total -= oldest.size
		items = items[1:]
	}
	return syncDirectory(s.quarantineDir)
}

func (s *ProbeSpool) signal() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}
