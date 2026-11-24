package skiptests_fmt

import (
	"fmt"

	"fakestringer"
)

// leak, without skip-tests this would be flagged.
func leak(p fakestringer.Plain) {
	fmt.Println(p)
}
