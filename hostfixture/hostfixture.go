// Package hostfixture builds the program images identity's script-host
// classifier reads (ID-I1, TD83) for tests: copies of the running test
// executable carrying an Electron fuse wire or a Bun standalone module graph,
// and synthetic Mach-O images carrying a __BUN segment or code-signature
// entitlements. Nothing is installed or run: no Electron, Bun, Node or Python
// is needed. Each marker is assembled at run time, so the test executable
// itself carries none of them.
package hostfixture

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func reversed(s string) []byte {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

var (
	electronSentinel = reversed("Xst9BaZBXHmKNWQjbbP697zNndGKp7Ld")
	bunTrailer       = reversed("\n---- !nuB ----\n")
	bunBeBun         = reversed("NUB_EB_NUB")
)

// Plain copies the running test executable, a program image the Go
// toolchain built for this test, to dir/name and returns its path.
func Plain(t testing.TB, dir, name string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	return write(t, dir, name, data)
}

func write(t testing.TB, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func executableBytes(t testing.TB) []byte {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Electron writes a copy of the test executable carrying Electron's fuse
// wire (version 1, nine fuses) with RunAsNode on or off, as
// @electron/fuses writes it into an Electron binary.
func Electron(t testing.TB, dir, name string, runAsNode bool) string {
	t.Helper()
	fuse := byte('0')
	if runAsNode {
		fuse = '1'
	}
	wire := append(bytes.Clone(electronSentinel), 1, 9, fuse, '1', '0', '0', '1', '1', '0', '0', '1')
	data := append(executableBytes(t), wire...)
	return write(t, dir, name, data)
}

// Bun writes a copy of the test executable carrying a Bun standalone
// module graph, as `bun build --compile` lays it out: a .bun PE section of a
// little-endian u64 length and the graph ending in the trailer on Windows,
// and the graph, the trailer and an eight-byte total at the end of the file
// elsewhere. beBun adds the BUN_BE_BUN name a Bun runtime from 1.2.16 on
// carries, in its own read-only section on Windows.
func Bun(t testing.TB, dir, name string, beBun bool) string {
	t.Helper()
	graph := append(bytes.Repeat([]byte{0x42}, 4096), make([]byte, 32)...) // modules, then Offsets
	graph = append(graph, bunTrailer...)
	data := executableBytes(t)
	if runtime.GOOS == "windows" {
		blob := binary.LittleEndian.AppendUint64(nil, uint64(len(graph)))
		data = addSection(t, data, ".bun", append(blob, graph...))
		if beBun {
			data = addSection(t, data, ".bunrt", append(bytes.Clone(bunBeBun), 0))
		}
		return write(t, dir, name, data)
	}
	if beBun {
		data = append(data, bunBeBun...)
	}
	data = append(data, graph...)
	data = binary.LittleEndian.AppendUint64(data, uint64(len(data)))
	return write(t, dir, name, data)
}

// addSection appends one initialized read-only section to a PE image, as a
// linker or Bun's compiler adds one: a section header after the last, its
// raw data at the end of the file aligned to FileAlignment, and the image
// size grown to cover it.
func addSection(t testing.TB, image []byte, name string, content []byte) []byte {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(image))
	if err != nil {
		t.Fatalf("not a PE image: %v", err)
	}
	le := binary.LittleEndian
	peOff := int(le.Uint32(image[0x3c:]))
	coff := peOff + 4
	optional := coff + 20
	sections := optional + int(f.FileHeader.SizeOfOptionalHeader)
	count := int(f.FileHeader.NumberOfSections)
	header := sections + 40*count
	sectionAlign := le.Uint32(image[optional+32:])
	fileAlign := le.Uint32(image[optional+36:])
	sizeOfHeaders := le.Uint32(image[optional+60:])
	if uint32(header+40) > sizeOfHeaders {
		t.Fatalf("no room for another section header in this image")
	}
	for _, s := range f.Sections {
		if s.Offset != 0 && uint32(header+40) > s.Offset {
			t.Fatalf("no room for another section header before the first section")
		}
	}
	var end uint32
	for _, s := range f.Sections {
		end = max(end, s.VirtualAddress+max(s.VirtualSize, s.Size))
	}
	virtual := align(end, sectionAlign)
	out := bytes.Clone(image)
	for uint32(len(out))%fileAlign != 0 {
		out = append(out, 0)
	}
	raw := uint32(len(out))
	out = append(out, content...)
	for uint32(len(out))%fileAlign != 0 {
		out = append(out, 0)
	}
	var h [40]byte
	copy(h[:8], name)
	le.PutUint32(h[8:], uint32(len(content)))
	le.PutUint32(h[12:], virtual)
	le.PutUint32(h[16:], align(uint32(len(content)), fileAlign))
	le.PutUint32(h[20:], raw)
	le.PutUint32(h[36:], 0x40000040) // initialized data, readable
	copy(out[header:], h[:])
	le.PutUint16(out[coff+2:], uint16(count+1))
	le.PutUint32(out[optional+56:], align(virtual+uint32(len(content)), sectionAlign))
	return out
}

func align(n, to uint32) uint32 { return (n + to - 1) / to * to }

// MachO writes a synthetic 64-bit Mach-O executable image: a __TEXT segment,
// a __BUN segment carrying a Bun module graph when bun is set (with the
// BUN_BE_BUN name in __TEXT, as a current Bun runtime carries it), and a code
// signature whose XML entitlements set each named entitlement true.
func MachO(t testing.TB, dir, name string, bun bool, entitlements ...string) string {
	t.Helper()
	return write(t, dir, name, machOBytes(bun, entitlements...))
}

// machOBytes is MachO's image.
func machOBytes(bun bool, entitlements ...string) []byte {
	le := binary.LittleEndian
	type segment struct {
		name string
		data []byte
	}
	segs := []segment{{"__TEXT", bytes.Repeat([]byte{0x90}, 64)}}
	if bun {
		// The runtime's own strings name the variable it honours.
		segs[0].data = append(segs[0].data, bunBeBun...)
		graph := append(bytes.Repeat([]byte{0x42}, 256), bunTrailer...)
		segs = append(segs, segment{"__BUN", append(le.AppendUint64(nil, uint64(len(graph))), graph...)})
	}
	var signature []byte
	if len(entitlements) > 0 {
		var xml bytes.Buffer
		xml.WriteString(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>`)
		for _, e := range entitlements {
			xml.WriteString("\n\t<key>" + e + "</key>\n\t<true/>")
		}
		xml.WriteString("</dict></plist>")
		be := binary.BigEndian
		blob := be.AppendUint32(nil, 0xfade7171)
		blob = be.AppendUint32(blob, uint32(8+xml.Len()))
		blob = append(blob, xml.Bytes()...)
		signature = be.AppendUint32(nil, 0xfade0cc0)
		signature = be.AppendUint32(signature, uint32(12+8+len(blob)))
		signature = be.AppendUint32(signature, 1)
		signature = be.AppendUint32(signature, 5) // CSSLOT_ENTITLEMENTS
		signature = be.AppendUint32(signature, 20)
		signature = append(signature, blob...)
	}
	ncmds := len(segs)
	sizeofcmds := (72 + 80) * len(segs)
	if signature != nil {
		ncmds++
		sizeofcmds += 16
	}
	offset := uint64(32 + sizeofcmds)
	var cmds []byte
	var body []byte
	for i, s := range segs {
		at := offset + uint64(len(body))
		cmd := le.AppendUint32(nil, 0x19) // LC_SEGMENT_64
		cmd = le.AppendUint32(cmd, 72+80)
		cmd = append(cmd, name16(s.name)...)
		cmd = le.AppendUint64(cmd, 0x100000000+uint64(i)*0x10000) // vmaddr
		cmd = le.AppendUint64(cmd, 0x10000)                       // vmsize
		cmd = le.AppendUint64(cmd, at)                            // fileoff
		cmd = le.AppendUint64(cmd, uint64(len(s.data)))           // filesize
		cmd = le.AppendUint32(cmd, 5)
		cmd = le.AppendUint32(cmd, 5)
		cmd = le.AppendUint32(cmd, 1) // nsects
		cmd = le.AppendUint32(cmd, 0)
		sect := name16("__" + s.name[2:])
		if s.name == "__BUN" {
			sect = name16("__bun")
		}
		cmd = append(cmd, sect...)
		cmd = append(cmd, name16(s.name)...)
		cmd = le.AppendUint64(cmd, 0x100000000+uint64(i)*0x10000)
		cmd = le.AppendUint64(cmd, uint64(len(s.data)))
		cmd = le.AppendUint32(cmd, uint32(at))
		cmd = append(cmd, make([]byte, 4*7)...) // align, reloff, nreloc, flags, reserved1-3
		cmds = append(cmds, cmd...)
		body = append(body, s.data...)
	}
	if signature != nil {
		at := offset + uint64(len(body))
		cmd := le.AppendUint32(nil, 0x1d) // LC_CODE_SIGNATURE
		cmd = le.AppendUint32(cmd, 16)
		cmd = le.AppendUint32(cmd, uint32(at))
		cmd = le.AppendUint32(cmd, uint32(len(signature)))
		cmds = append(cmds, cmd...)
		body = append(body, signature...)
	}
	head := le.AppendUint32(nil, 0xfeedfacf)
	head = le.AppendUint32(head, 0x01000007) // x86_64
	head = le.AppendUint32(head, 3)
	head = le.AppendUint32(head, 2) // MH_EXECUTE
	head = le.AppendUint32(head, uint32(ncmds))
	head = le.AppendUint32(head, uint32(sizeofcmds))
	head = le.AppendUint32(head, 0)
	head = le.AppendUint32(head, 0)
	return append(append(head, cmds...), body...)
}

func name16(s string) []byte {
	b := make([]byte, 16)
	copy(b, s)
	return b
}
