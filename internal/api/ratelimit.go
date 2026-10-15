package api

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

var rateState = struct {
	sync.Mutex
	m map[string]bucket
}{m: map[string]bucket{}}

func allowRate(id string, limit int) bool {
	if limit < 1 {
		limit = 60
	}
	now := time.Now()
	rateState.Lock()
	defer rateState.Unlock()
	b, ok := rateState.m[id]
	if !ok {
		b = bucket{tokens: float64(limit), last: now}
	}
	b.tokens += now.Sub(b.last).Seconds() * float64(limit) / 60
	if b.tokens > float64(limit) {
		b.tokens = float64(limit)
	}
	b.last = now
	if b.tokens < 1 {
		rateState.m[id] = b
		return false
	}
	b.tokens--
	rateState.m[id] = b
	return true
}
