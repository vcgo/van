package van

import "time"

// Sleep wait x millisecond
func Sleep(x int) {
	time.Sleep(time.Duration(x) * time.Millisecond)
}
