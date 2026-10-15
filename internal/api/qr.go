package api

import (
	"fmt"
	"strings"
)

// qrV5L encodes a short provisioning URI as a QR Model 2 version 5-L symbol.
// Version 5-L carries up to 106 bytes in byte mode and uses one RS block.
func qrSVG(payload string) (string, error) {
	const version, size, dataWords, eccWords = 5, 37, 108, 26
	if len(payload) > 106 {
		return "", fmt.Errorf("QR provisioning URI too long")
	}
	bits := make([]bool, 0, dataWords*8)
	appendBits := func(v uint32, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, ((v>>i)&1) != 0)
		}
	}
	appendBits(4, 4)
	appendBits(uint32(len(payload)), 8)
	for i := 0; i < len(payload); i++ {
		appendBits(uint32(payload[i]), 8)
	}
	capBits := dataWords * 8
	for i := 0; i < 4 && len(bits) < capBits; i++ {
		bits = append(bits, false)
	}
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	data := make([]byte, 0, dataWords)
	for i := 0; i < len(bits); i += 8 {
		var b byte
		for j := 0; j < 8; j++ {
			b <<= 1
			if bits[i+j] {
				b |= 1
			}
		}
		data = append(data, b)
	}
	for pad := byte(0xec); len(data) < dataWords; pad ^= 0xfd {
		data = append(data, pad)
	}
	gen := rsGenerator(eccWords)
	rem := make([]byte, eccWords)
	for _, b := range data {
		factor := b ^ rem[0]
		copy(rem, rem[1:])
		rem[len(rem)-1] = 0
		for j := range rem {
			rem[j] ^= gfMul(gen[j+1], factor)
		}
	}
	all := append(append([]byte{}, data...), rem...)
	m := make([][]bool, size)
	reserved := make([][]bool, size)
	for y := 0; y < size; y++ {
		m[y] = make([]bool, size)
		reserved[y] = make([]bool, size)
	}
	set := func(x, y int, v bool) {
		if x >= 0 && x < size && y >= 0 && y < size {
			m[y][x] = v
			reserved[y][x] = true
		}
	}
	finder := func(cx, cy int) {
		for dy := -1; dy <= 7; dy++ {
			for dx := -1; dx <= 7; dx++ {
				x, y := cx+dx, cy+dy
				v := dx >= 0 && dx <= 6 && dy >= 0 && dy <= 6 && (dx == 0 || dx == 6 || dy == 0 || dy == 6 || (dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4))
				set(x, y, v)
			}
		}
	}
	finder(0, 0)
	finder(size-7, 0)
	finder(0, size-7)
	// Version 5 has one non-overlapping alignment pattern at (30,30).
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			set(30+dx, 30+dy, maxInt(absInt(dx), absInt(dy)) != 1)
		}
	}
	for i := 8; i < size-8; i++ {
		set(6, i, i%2 == 0)
		set(i, 6, i%2 == 0)
	}
	// Format information for error correction L and mask 0.
	fmtData := uint32(1 << 3)
	v := fmtData << 10
	for i := 14; i >= 10; i-- {
		if ((v >> i) & 1) != 0 {
			v ^= 0x537 << uint(i-10)
		}
	}
	format := ((fmtData << 10) | (v & 0x3ff)) ^ 0x5412
	for i := 0; i <= 5; i++ {
		set(8, i, ((format>>uint(i))&1) != 0)
	}
	set(8, 7, ((format>>6)&1) != 0)
	set(8, 8, ((format>>7)&1) != 0)
	set(7, 8, ((format>>8)&1) != 0)
	for i := 9; i < 15; i++ {
		set(14-i, 8, ((format>>uint(i))&1) != 0)
	}
	for i := 0; i < 8; i++ {
		set(size-1-i, 8, ((format>>uint(i))&1) != 0)
	}
	for i := 8; i < 15; i++ {
		set(8, size-15+i, ((format>>uint(i))&1) != 0)
	}
	set(8, size-8, true)
	bit := 0
	upward := true
	for right := size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < size; vert++ {
			y := vert
			if upward {
				y = size - 1 - vert
			}
			for j := 0; j < 2; j++ {
				x := right - j
				if reserved[y][x] {
					continue
				}
				b := false
				if bit < len(all)*8 {
					b = ((all[bit/8] >> uint(7-bit%8)) & 1) != 0
				}
				bit++
				if (x+y)%2 == 0 {
					b = !b
				}
				m[y][x] = b
			}
		}
		upward = !upward
	}
	var out strings.Builder
	fmt.Fprintf(&out, `<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="TOTP 二维码" viewBox="-4 -4 %d %d" width="296" height="296" shape-rendering="crispEdges"><rect x="-4" y="-4" width="%d" height="%d" fill="white"/>`, size+8, size+8, size+8, size+8)
	out.WriteString(`<path fill="black" d="`)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if m[y][x] {
				fmt.Fprintf(&out, "M%d %dh1v1h-1z", x, y)
			}
		}
	}
	out.WriteString(`"/></svg>`)
	return out.String(), nil
}
func gfMul(x, y byte) byte {
	a, b, z := int(x), int(y), 0
	for b > 0 {
		if b&1 != 0 {
			z ^= a
		}
		b >>= 1
		a <<= 1
		if a&0x100 != 0 {
			a ^= 0x11d
		}
	}
	return byte(z)
}
func rsGenerator(degree int) []byte {
	p := []byte{1}
	root := byte(1)
	for i := 0; i < degree; i++ {
		q := make([]byte, len(p)+1)
		for j, c := range p {
			q[j] ^= c
			q[j+1] ^= gfMul(c, root)
		}
		p = q
		root = gfMul(root, 2)
	}
	return p
}
func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
