package jobs

import (
	"bytes"
	"fmt"
	"sync"
)

// DefaultMaxLogBytes is the default buffer capacity per job (2 MiB).
const DefaultMaxLogBytes = 2 << 20 // 2,097,152 bytes

// JobLogBuffer is a concurrency-safe, bounded memory buffer that captures
// subprocess stdout and stderr streams in real time via io.Writer, while allowing
// concurrent client chunked reads (ReadChunk) with byte offset tracking and EOF signaling.
type JobLogBuffer struct {
	mu        sync.RWMutex
	buf       bytes.Buffer
	maxBytes  int
	truncated bool
	eof       bool
}

// NewJobLogBuffer creates a JobLogBuffer with the specified byte capacity limit.
// If maxBytes <= 0, DefaultMaxLogBytes (2 MiB) is used.
func NewJobLogBuffer(maxBytes int) *JobLogBuffer {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxLogBytes
	}
	return &JobLogBuffer{
		maxBytes: maxBytes,
	}
}

// Write appends subprocess output to the buffer up to maxBytes.
// Excess bytes beyond maxBytes are discarded, truncated is marked true,
// and Write returns len(p), nil so the subprocess stdout/stderr pipe does not encounter broken pipe errors.
func (b *JobLogBuffer) Write(p []byte) (int, error) {
	totalLen := len(p)
	if totalLen == 0 {
		return 0, nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	remaining := b.maxBytes - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return totalLen, nil
	}

	if totalLen > remaining {
		_, _ = b.buf.Write(p[:remaining])
		b.truncated = true
		return totalLen, nil
	}

	_, _ = b.buf.Write(p)
	return totalLen, nil
}

// ReadChunk returns the logs starting from byte offset up to the current buffer length,
// the next offset for subsequent polling, whether output was truncated, and whether EOF was reached.
// If offset < 0, offset is normalized to 0.
// If offset >= current buffer length, an empty string is returned along with the current length.
func (b *JobLogBuffer) ReadChunk(offset int) (logs string, nextOffset int, truncated bool, eof bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	raw := b.buf.Bytes()
	currLen := len(raw)

	if offset < 0 {
		offset = 0
	}

	if offset >= currLen {
		return "", currLen, b.truncated, b.eof
	}

	chunk := string(raw[offset:])
	return chunk, currLen, b.truncated, b.eof
}

// SetEOF marks the log buffer as having reached the end of the subprocess stream.
// Once EOF is set, subsequent ReadChunk calls will return eof == true.
func (b *JobLogBuffer) SetEOF() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.eof = true
}

// IsEOF reports whether the buffer has reached EOF.
func (b *JobLogBuffer) IsEOF() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.eof
}

// Truncated reports whether the buffer reached maxBytes and truncated subsequent output.
func (b *JobLogBuffer) Truncated() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.truncated
}

// Len returns the current number of bytes stored in the buffer.
func (b *JobLogBuffer) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.buf.Len()
}

// String returns the full captured output as a string.
// If truncated, a notification footer is appended indicating the truncation threshold.
func (b *JobLogBuffer) String() string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.truncated {
		return fmt.Sprintf("%s\n[output truncated: exceeded %d bytes limit]", b.buf.String(), b.maxBytes)
	}
	return b.buf.String()
}

// Bytes returns a copy of the buffer's contents.
func (b *JobLogBuffer) Bytes() []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()

	out := make([]byte, b.buf.Len())
	copy(out, b.buf.Bytes())
	return out
}

// Reset clears the buffer, resetting truncated and eof flags.
func (b *JobLogBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.buf.Reset()
	b.truncated = false
	b.eof = false
}
