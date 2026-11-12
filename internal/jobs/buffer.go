package jobs

import (
	"fmt"
	"sync"
)

// DefaultMaxLogBytes is the default buffer capacity per job (2 MiB).
const DefaultMaxLogBytes = 2 << 20 // 2,097,152 bytes

// ChunkSize defines the fixed size of pooled byte arrays (16 KiB).
const ChunkSize = 16 * 1024 // 16,384 bytes

// chunkPool manages reusable 16 KiB fixed-size byte buffers to avoid heap churn.
// Using array pointers *[ChunkSize]byte avoids 24-byte slice interface boxing allocations on pool.Put.
var chunkPool = sync.Pool{
	New: func() any {
		return new([ChunkSize]byte)
	},
}

// JobLogBuffer is a concurrency-safe, chunked bounded memory buffer backed by sync.Pool
// that captures subprocess stdout and stderr streams in real time via io.Writer, while allowing
// concurrent client chunked reads (ReadChunk, ReadLogs) with byte offset tracking and EOF signaling.
type JobLogBuffer struct {
	mu        sync.RWMutex
	chunks    []*[ChunkSize]byte
	length    int
	maxBytes  int
	truncated bool
	eof       bool
	closed    bool
}

// NewJobLogBuffer creates a JobLogBuffer with the specified byte capacity limit.
// If maxBytes <= 0, DefaultMaxLogBytes (2 MiB) is used.
func NewJobLogBuffer(maxBytes int) *JobLogBuffer {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxLogBytes
	}
	initialCap := 4
	if maxChunks := (maxBytes + ChunkSize - 1) / ChunkSize; initialCap > maxChunks {
		initialCap = maxChunks
	}
	return &JobLogBuffer{
		maxBytes: maxBytes,
		chunks:   make([]*[ChunkSize]byte, 0, initialCap),
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

	if b.closed {
		// Drop writes if buffer has been closed to prevent pipe errors
		return totalLen, nil
	}

	remaining := b.maxBytes - b.length
	if remaining <= 0 {
		b.truncated = true
		return totalLen, nil
	}

	toWrite := totalLen
	if toWrite > remaining {
		toWrite = remaining
		b.truncated = true
	}

	written := 0
	for written < toWrite {
		chunkOffset := b.length % ChunkSize
		if chunkOffset == 0 {
			chunk := chunkPool.Get().(*[ChunkSize]byte)
			b.chunks = append(b.chunks, chunk)
		}

		currentChunk := b.chunks[len(b.chunks)-1]
		chunkSpace := ChunkSize - chunkOffset
		n := toWrite - written
		if n > chunkSpace {
			n = chunkSpace
		}

		copy(currentChunk[chunkOffset:chunkOffset+n], p[written:written+n])
		b.length += n
		written += n
	}

	return totalLen, nil
}

// copyRange copies count bytes from the chunk list starting at byte offset into dest.
// Assumes caller holds at least b.mu.RLock().
func (b *JobLogBuffer) copyRange(dest []byte, offset, count int) {
	copied := 0
	for copied < count {
		currOffset := offset + copied
		chunkIdx := currOffset / ChunkSize
		intraOffset := currOffset % ChunkSize
		chunkSpace := ChunkSize - intraOffset
		n := count - copied
		if n > chunkSpace {
			n = chunkSpace
		}

		copy(dest[copied:copied+n], b.chunks[chunkIdx][intraOffset:intraOffset+n])
		copied += n
	}
}

// ReadLogs reads up to limit bytes starting at offset across chunks.
// If limit <= 0, all available bytes from offset to current length are returned.
// Returns log string, nextOffset for subsequent polling, truncated flag, and EOF flag.
func (b *JobLogBuffer) ReadLogs(offset, limit int) (logs string, nextOffset int, truncated bool, eof bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if offset < 0 {
		offset = 0
	}

	currLen := b.length
	if offset >= currLen {
		return "", currLen, b.truncated, b.eof
	}

	available := currLen - offset
	toRead := available
	if limit > 0 && limit < toRead {
		toRead = limit
	}

	out := make([]byte, toRead)
	b.copyRange(out, offset, toRead)
	return string(out), offset + toRead, b.truncated, b.eof
}

// ReadChunk returns the logs starting from byte offset up to the current buffer length,
// the next offset for subsequent polling, whether output was truncated, and whether EOF was reached.
// If offset < 0, offset is normalized to 0.
// If offset >= current buffer length, an empty string is returned along with the current length.
func (b *JobLogBuffer) ReadChunk(offset int) (logs string, nextOffset int, truncated bool, eof bool) {
	return b.ReadLogs(offset, 0)
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
	return b.length
}

// String returns the full captured output as a string.
// If truncated, a notification footer is appended indicating the truncation threshold.
func (b *JobLogBuffer) String() string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var raw string
	if b.length > 0 {
		out := make([]byte, b.length)
		b.copyRange(out, 0, b.length)
		raw = string(out)
	}
	if b.truncated {
		return fmt.Sprintf("%s\n[output truncated: exceeded %d bytes limit]", raw, b.maxBytes)
	}
	return raw
}

// Bytes returns a copy of the buffer's contents.
func (b *JobLogBuffer) Bytes() []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.length == 0 {
		return []byte{}
	}
	out := make([]byte, b.length)
	b.copyRange(out, 0, b.length)
	return out
}

// Reset clears the buffer, returning chunks to sync.Pool and resetting truncated and eof flags.
func (b *JobLogBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i, c := range b.chunks {
		clear(c[:])
		chunkPool.Put(c)
		b.chunks[i] = nil
	}
	b.chunks = b.chunks[:0]
	b.length = 0
	b.truncated = false
	b.eof = false
	b.closed = false
}

// Close marks the buffer as closed and EOF, clears chunk memory to prevent
// cross-job data leakage, and returns all chunks to sync.Pool.
// Subsequent calls to Close are safe and return nil.
func (b *JobLogBuffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}
	b.closed = true
	b.eof = true
	for i, c := range b.chunks {
		clear(c[:])
		chunkPool.Put(c)
		b.chunks[i] = nil
	}
	b.chunks = nil
	b.length = 0
	return nil
}

// Release releases all chunks back to sync.Pool. It is an alias for Close.
func (b *JobLogBuffer) Release() {
	_ = b.Close()
}
