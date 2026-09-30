package plugin

import (
	"sync"
	"time"
)

// journalSize — сколько последних строк лога плагина помнит панель.
const journalSize = 200

// LogLine — строка лога плагина.
type LogLine struct {
	At   time.Time `json:"at"`
	Text string    `json:"text"`
}

// journal — последние строки лога одного плагина. Живёт в менеджере, а не
// в экземпляре: после перезапуска плагина видно, из-за чего он упал.
type journal struct {
	mu    sync.Mutex
	lines []LogLine
	next  int
	full  bool
}

func (j *journal) add(text string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lines == nil {
		j.lines = make([]LogLine, journalSize)
	}
	j.lines[j.next] = LogLine{At: time.Now(), Text: text}
	j.next = (j.next + 1) % journalSize
	if j.next == 0 {
		j.full = true
	}
}

// snapshot — строки, старые первыми.
func (j *journal) snapshot() []LogLine {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.full {
		return append([]LogLine(nil), j.lines[:j.next]...)
	}
	return append(append([]LogLine(nil), j.lines[j.next:]...), j.lines[:j.next]...)
}
