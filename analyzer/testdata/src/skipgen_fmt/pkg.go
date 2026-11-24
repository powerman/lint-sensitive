package skipgen_fmt

import (
	"fmt"

	"fakestringer"
)

func NotGenerated(p fakestringer.Plain) {
	fmt.Println(p) // want "printed with %v exposes"
}
