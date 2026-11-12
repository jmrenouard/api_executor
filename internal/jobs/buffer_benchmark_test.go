package jobs

import (
	"bytes"
	"sync"
	"testing"
)

// BenchmarkJobLogBuffer_Write benchmarks sequential write throughput and heap allocations
// across multiple payload sizes (128 B, 4 KiB, 32 KiB) up to 1 MiB and 2 MiB capacity.
func BenchmarkJobLogBuffer_Write(b *testing.B) {
	sizes := []struct {
		name      string
		chunkSize int
		totalSize int
	}{
		{"Line_128B_to_64KB", 128, 64 * 1024},
		{"Block_4KB_to_1MB", 4 * 1024, 1024 * 1024},
		{"Burst_32KB_to_2MB", 32 * 1024, 2 * 1024 * 1024},
	}

	for _, sc := range sizes {
		b.Run(sc.name, func(b *testing.B) {
			data := bytes.Repeat([]byte("X"), sc.chunkSize)
			b.ReportAllocs()
			b.SetBytes(int64(sc.totalSize))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				buf := NewJobLogBuffer(sc.totalSize)
				writes := sc.totalSize / sc.chunkSize
				for w := 0; w < writes; w++ {
					_, _ = buf.Write(data)
				}
				buf.Release()
			}
		})
	}
}

// BenchmarkJobLogBuffer_Concurrent benchmarks concurrent write and chunk read operations
// under parallel goroutines simulating worker pool execution.
func BenchmarkJobLogBuffer_Concurrent(b *testing.B) {
	data := bytes.Repeat([]byte("L"), 512)
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := NewJobLogBuffer(DefaultMaxLogBytes)
			for i := 0; i < 20; i++ {
				_, _ = buf.Write(data)
				if i%5 == 0 {
					_, _, _, _ = buf.ReadChunk(0)
				}
			}
			buf.SetEOF()
			buf.Release()
		}
	})
}

// BenchmarkJobLogBuffer_ReadChunk benchmarks chunked read latency and allocation efficiency
// at offset 0, mid-buffer, and near EOF on a 1 MiB populated buffer.
func BenchmarkJobLogBuffer_ReadChunk(b *testing.B) {
	buf := NewJobLogBuffer(DefaultMaxLogBytes)
	block := bytes.Repeat([]byte("M"), 4096)
	for i := 0; i < 256; i++ { // 1 MiB populated
		_, _ = buf.Write(block)
	}
	defer buf.Release()

	offsets := []struct {
		name   string
		offset int
	}{
		{"Offset_Start", 0},
		{"Offset_Mid_512KB", 512 * 1024},
		{"Offset_EOF_1MB", 1024 * 1024},
	}

	for _, tc := range offsets {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, _, _ = buf.ReadChunk(tc.offset)
			}
		})
	}
}

// BenchmarkJobLogBuffer_PoolRecycle benchmarks raw chunk acquisition and recycling cycles.
func BenchmarkJobLogBuffer_PoolRecycle(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := NewJobLogBuffer(DefaultMaxLogBytes)
		_, _ = buf.Write([]byte("quick line of log output\n"))
		buf.Release()
	}
}

// TestJobLogBuffer_ReadLogsRange verifies bounded range reads across chunk boundaries.
func TestJobLogBuffer_ReadLogsRange(t *testing.T) {
	buf := NewJobLogBuffer(DefaultMaxLogBytes)
	defer buf.Release()

	// Write 40 KiB of patterned data spanning multiple 16 KiB chunks
	payload := make([]byte, 40*1024)
	for i := range payload {
		payload[i] = byte('A' + (i % 26))
	}
	n, err := buf.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("unexpected write failure: n=%d, err=%v", n, err)
	}

	// 1. Read bounded range spanning chunks (offset 16000, limit 1000)
	logs, nextOffset, truncated, eof := buf.ReadLogs(16000, 1000)
	if len(logs) != 1000 {
		t.Fatalf("expected 1000 bytes, got %d", len(logs))
	}
	if nextOffset != 17000 {
		t.Fatalf("expected nextOffset 17000, got %d", nextOffset)
	}
	if truncated || eof {
		t.Fatalf("unexpected truncated=%v eof=%v", truncated, eof)
	}
	if logs != string(payload[16000:17000]) {
		t.Fatalf("data mismatch across chunk boundary")
	}

	// 2. Read past end
	emptyLogs, next, _, _ := buf.ReadLogs(50000, 100)
	if emptyLogs != "" || next != 40*1024 {
		t.Fatalf("expected empty logs and next=40960, got %q, %d", emptyLogs, next)
	}

	// 3. Negative offset normalizes to 0
	startLogs, startNext, _, _ := buf.ReadLogs(-10, 10)
	if len(startLogs) != 10 || startNext != 10 {
		t.Fatalf("expected 10 bytes from start, got len=%d next=%d", len(startLogs), startNext)
	}
	if startLogs != string(payload[:10]) {
		t.Fatalf("data mismatch on negative offset normalization")
	}
}

// TestJobLogBuffer_PoolWipingAndNoLeakage verifies that recycled chunks are zeroed
// and do not leak data across separate JobLogBuffer instances.
func TestJobLogBuffer_PoolWipingAndNoLeakage(t *testing.T) {
	// Step 1: Create buffer A, write secret data, and release to pool
	secret := bytes.Repeat([]byte("SECRET_API_TOKEN_12345!"), 100)
	bufA := NewJobLogBuffer(DefaultMaxLogBytes)
	_, _ = bufA.Write(secret)
	bufA.Release()

	// Step 2: Create buffer B (which may draw recycled chunk from pool)
	bufB := NewJobLogBuffer(DefaultMaxLogBytes)
	defer bufB.Release()

	// Write only a short greeting
	greeting := []byte("hello world")
	_, _ = bufB.Write(greeting)

	// Verify buffer B only contains the greeting
	if bufB.Len() != len(greeting) {
		t.Fatalf("expected len=%d, got %d", len(greeting), bufB.Len())
	}
	read, _, _, _ := bufB.ReadChunk(0)
	if read != "hello world" {
		t.Fatalf("expected 'hello world', got %q", read)
	}
	if bytes.Contains(bufB.Bytes(), []byte("SECRET_API_TOKEN")) {
		t.Fatalf("detected data leakage from recycled chunk in pool!")
	}
}

// TestJobLogBuffer_CloseIdempotency verifies calling Close or Release multiple times
// is safe and does not double-put chunks into sync.Pool.
func TestJobLogBuffer_CloseIdempotency(t *testing.T) {
	buf := NewJobLogBuffer(DefaultMaxLogBytes)
	_, _ = buf.Write([]byte("some data to populate chunks"))

	// Multiple sequential close calls
	for i := 0; i < 5; i++ {
		if err := buf.Close(); err != nil {
			t.Fatalf("iteration %d: Close returned error: %v", i, err)
		}
	}
	buf.Release() // Alias check

	// Writes after close should be safely ignored and not panic
	n, err := buf.Write([]byte("post close write"))
	if err != nil || n != len("post close write") {
		t.Fatalf("expected safe write drop, got n=%d, err=%v", n, err)
	}

	// Reads after close should report EOF
	logs, next, _, eof := buf.ReadChunk(0)
	if logs != "" || next != 0 || !eof {
		t.Fatalf("expected empty EOF read on closed buffer, got logs=%q, next=%d, eof=%v", logs, next, eof)
	}
}

// TestJobLogBuffer_ConcurrentCloseAndReaders tests that closing a buffer while concurrent
// readers are polling does not panic or trigger a data race.
func TestJobLogBuffer_ConcurrentCloseAndReaders(t *testing.T) {
	buf := NewJobLogBuffer(DefaultMaxLogBytes)
	_, _ = buf.Write(bytes.Repeat([]byte("concurrent test data\n"), 200))

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			<-start
			for j := 0; j < 50; j++ {
				_, _, _, _ = buf.ReadChunk(j * 10)
				_, _, _, _ = buf.ReadLogs(j*5, 20)
				_ = buf.Len()
				_ = buf.IsEOF()
			}
		}(i)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_ = buf.Close()
	}()

	close(start)
	wg.Wait()
}
