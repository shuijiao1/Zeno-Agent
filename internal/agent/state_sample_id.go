package agent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

var stateSampleIDSequence atomic.Uint64

func withNewStateSampleIdentifiers(sample StateSample, ts time.Time) StateSample {
	id := newStateSampleID(ts)
	sample.SampleID = id
	sample.IdempotencyKey = id
	return sample
}

func ensureStateSampleIdentifiers(sample StateSample) StateSample {
	id := strings.TrimSpace(sample.SampleID)
	if id == "" {
		id = strings.TrimSpace(sample.IdempotencyKey)
	}
	if id == "" {
		id = deterministicStateSampleID(sample)
	}
	sample.SampleID = id
	sample.IdempotencyKey = id
	return sample
}

func newStateSampleID(ts time.Time) string {
	var randomBytes [16]byte
	if _, err := rand.Read(randomBytes[:]); err == nil {
		return "state-" + hex.EncodeToString(randomBytes[:])
	}
	fallback := fmt.Sprintf("%d:%d", ts.UTC().UnixNano(), stateSampleIDSequence.Add(1))
	digest := sha256.Sum256([]byte(fallback))
	return "state-" + hex.EncodeToString(digest[:16])
}

func deterministicStateSampleID(sample StateSample) string {
	copy := sample
	copy.SampleID = ""
	copy.IdempotencyKey = ""
	payload, err := json.Marshal(copy)
	if err != nil {
		payload = []byte(fmt.Sprintf("%+v", copy))
	}
	digest := sha256.Sum256(payload)
	return "state-" + hex.EncodeToString(digest[:16])
}
