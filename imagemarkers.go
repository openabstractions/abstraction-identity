package identity

import (
	"bytes"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The markers a program image carries when its publisher's code can be made
// to run someone else's (TD83, security-5). Each needle is kept reversed in
// this source and turned around at start, so no program that links this
// package carries the forward bytes and reads as marked itself.
var (
	// electronSentinel precedes Electron's fuse wire: one version byte (1),
	// one length byte, then one byte per fuse, RunAsNode first; '0' is off
	// and 'r' removed (electron/fuses src/constants.ts and config.ts).
	electronSentinel = reversed("Xst9BaZBXHmKNWQjbbP697zNndGKp7Ld")
	// bunTrailer ends a Bun standalone executable's module graph
	// (oven-sh/bun src/StandaloneModuleGraph.zig, bun-v1.3.9).
	bunTrailer = reversed("\n---- !nuB ----\n")
	// bunBeBun is the environment variable a Bun runtime honours since
	// 1.2.16: with it set, a standalone executable runs as the bun CLI and
	// runs any script (https://bun.com/docs/bundler/executables). A runtime
	// that reads it carries its name.
	bunBeBun = reversed("NUB_EB_NUB")
)

func reversed(s string) []byte {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

// The macOS entitlements that let code from outside the signed image run in
// the program (Hardened Runtime; security-5, TD88).
var foreignCodeEntitlements = []string{
	"com.apple.security.cs.allow-dyld-environment-variables",
	"com.apple.security.cs.disable-library-validation",
	"com.apple.security.get-task-allow",
}

// Evidence words for Code.ForeignCode.
const (
	// ForeignCodeSharedInterpreter: the program is a shared interpreter.
	ForeignCodeSharedInterpreter = "shared-interpreter"
	// ForeignCodeAppInterpreter: the program is an application's own
	// interpreter copy: a program the name tables or its signature name that
	// sits beside its own pyvenv.cfg whose home is another folder. P-J10's
	// host-kit marker joins this evidence when P-J10 lands.
	ForeignCodeAppInterpreter = "app-interpreter"
	// ForeignCodeElectronRunAsNode: Electron's RunAsNode fuse is on.
	ForeignCodeElectronRunAsNode = "electron-run-as-node"
	// ForeignCodeBunBeBun: a Bun standalone executable whose runtime honours
	// the variable that makes it the bun CLI.
	ForeignCodeBunBeBun = "bun-be-bun"
	// ForeignCodeEntitlementPrefix precedes the macOS entitlement named.
	ForeignCodeEntitlementPrefix = "macos-entitlement:"
)

// maxImageScan bounds the bytes one image scan reads; a larger file is not
// scanned and carries no marker evidence.
const maxImageScan = 2 << 30

// ImageForeignCode reads a program image for the markers that make it run
// foreign code and returns the evidence word, or "" for none: Electron's
// fuse wire with RunAsNode on, a Bun standalone executable (the .bun PE
// section, the __BUN Mach-O segment or the trailer at the end of the file)
// whose runtime honours BUN_BE_BUN, and a Mach-O code signature whose
// entitlements allow foreign code. It reads r as one file of size bytes.
func ImageForeignCode(r io.ReaderAt, size int64) (string, error) {
	if size < 0 || size > maxImageScan {
		return "", fmt.Errorf("an image of %d bytes is not scanned", size)
	}
	if entitlement := machoEntitlement(r, size); entitlement != "" {
		return ForeignCodeEntitlementPrefix + entitlement, nil
	}
	runAsNode, honoured, err := scanImage(r, size)
	if err != nil {
		return "", err
	}
	if runAsNode {
		return ForeignCodeElectronRunAsNode, nil
	}
	if honoured && bunStandalone(r, size) {
		return ForeignCodeBunBeBun, nil
	}
	return "", nil
}

// scanImage reads the whole image once for Electron's fuse wire and the
// BUN_BE_BUN name. RunAsNode reads on for any fuse byte other than '0' and
// 'r', so an unknown state fails closed.
func scanImage(r io.ReaderAt, size int64) (runAsNode, honoured bool, err error) {
	const chunk = 4 << 20
	keep := len(electronSentinel) + 3
	buf := make([]byte, 0, chunk+keep)
	for off := int64(0); off < size; {
		n := int64(chunk)
		if size-off < n {
			n = size - off
		}
		start := len(buf)
		buf = buf[:start+int(n)]
		if _, err := r.ReadAt(buf[start:], off); err != nil && !errors.Is(err, io.EOF) {
			return false, false, err
		}
		off += n
		last := off >= size
		if bytes.Contains(buf, bunBeBun) {
			honoured = true
		}
		for rest := buf; ; {
			i := bytes.Index(rest, electronSentinel)
			if i < 0 {
				break
			}
			wire := rest[i+len(electronSentinel):]
			if len(wire) < 3 {
				if !last {
					break // the next chunk carries the wire
				}
			} else if wire[0] == 1 && wire[1] >= 1 && wire[2] != '0' && wire[2] != 'r' {
				runAsNode = true
			}
			rest = rest[i+1:]
		}
		if runAsNode && honoured || last {
			break
		}
		// The next chunk starts with this one's last bytes, so a needle or a
		// fuse wire across the boundary is read whole there.
		if len(buf) > keep {
			buf = append(buf[:0], buf[len(buf)-keep:]...)
		}
	}
	return runAsNode, honoured, nil
}

// bunStandalone reports whether the image carries a Bun standalone module
// graph: a .bun PE section or __BUN Mach-O segment whose declared data (a
// little-endian u64 length, then the data) ends with the trailer, or, the
// Linux layout, the trailer followed by an eight-byte total at the end of
// the file.
func bunStandalone(r io.ReaderAt, size int64) bool {
	if f, err := pe.NewFile(io.NewSectionReader(r, 0, size)); err == nil {
		if s := f.Section(".bun"); s != nil && blobEndsWithTrailer(s, int64(s.Size)) {
			return true
		}
	}
	for _, f := range machoFiles(r, size) {
		if seg := f.Segment("__BUN"); seg != nil {
			if blobEndsWithTrailer(seg, int64(seg.Filesz)) {
				return true
			}
		}
	}
	if size >= int64(len(bunTrailer))+8 {
		tail := make([]byte, len(bunTrailer)+8)
		if _, err := r.ReadAt(tail, size-int64(len(tail))); err == nil && bytes.Equal(tail[:len(bunTrailer)], bunTrailer) {
			return true
		}
	}
	return false
}

// blobEndsWithTrailer reads a length-prefixed blob and reports whether its
// declared data ends with the Bun trailer.
func blobEndsWithTrailer(r io.ReaderAt, size int64) bool {
	var head [8]byte
	if size < 8 {
		return false
	}
	if _, err := r.ReadAt(head[:], 0); err != nil {
		return false
	}
	n := binary.LittleEndian.Uint64(head[:])
	if n < uint64(len(bunTrailer)) || n > uint64(size-8) {
		return false
	}
	end := make([]byte, len(bunTrailer))
	if _, err := r.ReadAt(end, 8+int64(n)-int64(len(end))); err != nil {
		return false
	}
	return bytes.Equal(end, bunTrailer)
}

// machoFiles is the image as Mach-O files: one for a thin image, one per
// architecture for a universal one, none otherwise.
func machoFiles(r io.ReaderAt, size int64) []*macho.File {
	sr := io.NewSectionReader(r, 0, size)
	if f, err := macho.NewFile(sr); err == nil {
		return []*macho.File{f}
	}
	fat, err := macho.NewFatFile(sr)
	if err != nil {
		return nil
	}
	var out []*macho.File
	for _, arch := range fat.Arches {
		out = append(out, arch.File)
	}
	return out
}

// Mach-O code signature constants (Apple's cs_blobs.h).
const (
	loadCodeSignature   = 0x1d
	csMagicSuperBlob    = 0xfade0cc0
	csMagicEntitlements = 0xfade7171
	maxSignatureBytes   = 16 << 20
)

// machoEntitlement returns the first foreign-code entitlement the image's
// code signature grants with <true/>, or "". The entitlements are read from
// the embedded signature's XML blob; a signature the platform would refuse
// still names what it asks for, so a forged blob only marks its own image.
func machoEntitlement(r io.ReaderAt, size int64) string {
	for _, f := range machoFiles(r, size) {
		for _, load := range f.Loads {
			raw := load.Raw()
			if len(raw) < 16 || f.ByteOrder.Uint32(raw[0:4]) != loadCodeSignature {
				continue
			}
			off, n := int64(f.ByteOrder.Uint32(raw[8:12])), int64(f.ByteOrder.Uint32(raw[12:16]))
			if n < 12 || n > maxSignatureBytes {
				continue
			}
			base := machoBase(f, r, size)
			blob := make([]byte, n)
			if _, err := r.ReadAt(blob, base+off); err != nil {
				continue
			}
			if name := entitlementIn(blob); name != "" {
				return name
			}
		}
	}
	return ""
}

// machoBase is where f starts within the file: zero for a thin image, the
// architecture's offset in a universal one.
func machoBase(f *macho.File, r io.ReaderAt, size int64) int64 {
	fat, err := macho.NewFatFile(io.NewSectionReader(r, 0, size))
	if err != nil {
		return 0
	}
	for _, arch := range fat.Arches {
		if arch.File.Cpu == f.Cpu && arch.File.SubCpu == f.SubCpu {
			return int64(arch.Offset)
		}
	}
	return 0
}

// entitlementIn reads a code signature super blob, big-endian, and returns
// the first foreign-code entitlement its XML entitlements blob sets true.
func entitlementIn(sig []byte) string {
	be := binary.BigEndian
	if len(sig) < 12 || be.Uint32(sig) != csMagicSuperBlob {
		return ""
	}
	count := int(be.Uint32(sig[8:12]))
	for i := 0; i < count && 12+8*i+8 <= len(sig); i++ {
		off := int(be.Uint32(sig[12+8*i+4:]))
		if off < 0 || off+8 > len(sig) || be.Uint32(sig[off:]) != csMagicEntitlements {
			continue
		}
		n := int(be.Uint32(sig[off+4:]))
		if n < 8 || off+n > len(sig) {
			continue
		}
		xml := sig[off+8 : off+n]
		for _, name := range foreignCodeEntitlements {
			if entitlementTrue(xml, name) {
				return name
			}
		}
	}
	return ""
}

// entitlementTrue reports whether the plist sets the key true.
func entitlementTrue(xml []byte, name string) bool {
	key := []byte("<key>" + name + "</key>")
	for rest := xml; ; {
		i := bytes.Index(rest, key)
		if i < 0 {
			return false
		}
		rest = rest[i+len(key):]
		if bytes.HasPrefix(bytes.TrimLeft(rest, " \t\r\n"), []byte("<true/>")) {
			return true
		}
	}
}

// foreignImages caches the marker evidence of a program file by its stamp,
// so a large image is read once.
var foreignImages fileCache[string]

// imageForeignCodeFile reads the marker evidence of the program file at
// program. A path that is relative or refused by LocalPath, a missing file
// and a failed read are no evidence, and a failure is not remembered. The
// evidence is remembered only when the file's stamp after the read is the
// stamp before it.
func imageForeignCodeFile(program string) string {
	f, info, stamp, ok := openStamped(program)
	if !ok {
		return ""
	}
	defer f.Close()
	if evidence, ok := foreignImages.get(stamp); ok {
		return evidence
	}
	evidence, err := ImageForeignCode(f, info.Size())
	if err != nil {
		return ""
	}
	foreignImages.keep(f, stamp, evidence)
	return evidence
}
