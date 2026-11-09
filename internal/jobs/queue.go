package jobs

import (
	"container/heap"
	"errors"
	"sync"
)

var (
	ErrQueueFull   = errors.New("job queue is full")
	ErrQueueClosed = errors.New("job queue is closed")
	ErrJobNotFound = errors.New("job not found in queue")
)

// priorityQueue implements heap.Interface for *Job.
type priorityQueue []*Job

func (pq priorityQueue) Len() int { return len(pq) }

func (pq priorityQueue) Less(i, j int) bool {
	wi := pq[i].Priority.Weight()
	wj := pq[j].Priority.Weight()
	if wi != wj {
		return wi > wj // Higher priority weight pops first
	}
	// FIFO tie-breaking within same priority tier
	if !pq[i].CreatedAt.Equal(pq[j].CreatedAt) {
		return pq[i].CreatedAt.Before(pq[j].CreatedAt)
	}
	return pq[i].GetQueueSeq() < pq[j].GetQueueSeq()
}

func (pq priorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].SetHeapIndex(i)
	pq[j].SetHeapIndex(j)
}

func (pq *priorityQueue) Push(x any) {
	n := len(*pq)
	item := x.(*Job)
	item.SetHeapIndex(n)
	*pq = append(*pq, item)
}

func (pq *priorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil // Avoid memory leak
	item.SetHeapIndex(-1)
	*pq = old[0 : n-1]
	return item
}

// JobQueue provides a thread-safe, bounded priority queue with sync.Cond signaling.
type JobQueue struct {
	mu       sync.Mutex
	cond     *sync.Cond
	pq       priorityQueue
	lookup   map[string]*Job
	capacity int
	closed   bool
	seq      int64
}

// NewJobQueue creates a priority queue with optional bounded capacity (0 or negative = unbounded).
func NewJobQueue(capacity int) *JobQueue {
	q := &JobQueue{
		capacity: capacity,
		pq:       make(priorityQueue, 0),
		lookup:   make(map[string]*Job),
	}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// Enqueue inserts a job into the queue, waking a waiting worker.
func (q *JobQueue) Enqueue(job *Job) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return ErrQueueClosed
	}
	if q.capacity > 0 && len(q.pq) >= q.capacity {
		return ErrQueueFull
	}
	q.seq++
	job.SetQueueSeq(q.seq)
	heap.Push(&q.pq, job)
	q.lookup[job.ID] = job
	q.cond.Signal()
	return nil
}

// Dequeue pops the highest priority job, blocking until a job arrives or the queue is closed.
func (q *JobQueue) Dequeue() (*Job, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for len(q.pq) == 0 && !q.closed {
		q.cond.Wait()
	}
	if q.closed && len(q.pq) == 0 {
		return nil, ErrQueueClosed
	}
	item := heap.Pop(&q.pq).(*Job)
	delete(q.lookup, item.ID)
	return item, nil
}

// Remove extracts a job from the queue by ID in O(log N) time if still queued.
func (q *JobQueue) Remove(jobID string) (*Job, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	job, exists := q.lookup[jobID]
	if !exists || job.GetHeapIndex() < 0 {
		return nil, false
	}
	heap.Remove(&q.pq, job.GetHeapIndex())
	delete(q.lookup, jobID)
	job.SetHeapIndex(-1)
	return job, true
}

// Close marks the queue as closed and wakes all waiting workers.
func (q *JobQueue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return
	}
	q.closed = true
	q.cond.Broadcast()
}

// Len returns the current count of queued jobs.
func (q *JobQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pq)
}

// Capacity returns the maximum configured capacity of the queue.
func (q *JobQueue) Capacity() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.capacity
}

// IsClosed returns whether the queue has been closed.
func (q *JobQueue) IsClosed() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.closed
}
