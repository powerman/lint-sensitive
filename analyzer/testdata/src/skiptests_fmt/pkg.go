package skiptests_fmt

import (
	"fmt"

	"fakestringer"
)

func NotTestFile(p fakestringer.Plain) {
	fmt.Println(p) // want "printed with %v exposes"
}
