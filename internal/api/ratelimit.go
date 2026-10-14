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

func allowRate(id string) bool {
	now := time.Now()
	rateState.Lock()
	defer rateState.Unlock()
	b, ok := rateState.m[id]
	if !ok {
		b = bucket{tokens: 60, last: now}
	}
	b.tokens += now.Sub(b.last).Seconds()
	if b.tokens > 60 {
		b.tokens = 60
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
