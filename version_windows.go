//go:build windows

package identity

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// imageVersion is the program-naming part of an image's version resource:
// FileDescription and OriginalFilename (VISION 2026-10-01). A prompt names a
// trusted program by them, the way UAC names one by its FileDescription.
type imageVersion struct {
	description  string
	originalName string
}

// verifyHeld runs the Authenticode policy over the held file, names its
// signer, and adds the version resource of a trusted file. The resource is
// read from the held handle before and after the verification, and the two
// reads must agree, so the strings come from the bytes Windows verified: a
// change in between is an error, as a path that moved is (stillSameFile).
// Neither a running image (its mapped section) nor a file VerifyFile holds
// (verifyFileShare) can be opened for writing during the span; the second
// read is the check that does not rest on either. A trusted file whose
// resource could not be read (an I/O failure, errUnreadable) is abandoned
// too: no resource and an unread one are different answers. A file with no
// resource, or one that does not parse, names nothing. GetFileVersionInfo is
// not used: it reads by path, and for a file with a language resource file
// it returns the .mui's resource (powershell.exe's reads OriginalFilename
// PowerShell.EXE.MUI).
func verifyHeld(file windows.Handle, pathW *uint16, revocation bool) (Code, Proof, error) {
	before, beforeErr := heldVersion(file)
	code, verdict := verifyTrust(file, pathW, revocation)
	code = withSigner(code, pathW)
	if !code.Trusted {
		return code, verdict, nil
	}
	after, afterErr := heldVersion(file)
	if errors.Is(beforeErr, errUnreadable) || errors.Is(afterErr, errUnreadable) {
		return Code{}, ProofNone, fmt.Errorf("the file's version resource could not be read: %w", errors.Join(beforeErr, afterErr))
	}
	if after != before || (beforeErr == nil) != (afterErr == nil) {
		return Code{}, ProofNone, errors.New("the file's version resource changed during verification")
	}
	code.Description, code.OriginalName = after.description, after.originalName
	return code, verdict, nil
}

// heldVersion reads the version resource through the held handle with
// positioned reads, then returns the handle's file pointer to the start, where
// the open left it for the verification. A file with no version resource, or
// one that does not parse, has none.
func heldVersion(file windows.Handle) (imageVersion, error) {
	version, err := readVersionResource(versionSource(file))
	//unchecked: the pointer is restored for a later reader of the handle; the positioned reads above do not depend on it
	windows.Seek(file, 0, io.SeekStart)
	return version, err
}

// versionSource is the reader heldVersion parses; tests make it fail.
var versionSource = func(file windows.Handle) io.ReaderAt { return heldFile(file) }

// errUnreadable marks a read the operating system failed, as distinct from a
// resource that is absent, truncated or malformed.
var errUnreadable = errors.New("the file could not be read")

// heldFile reads an open, synchronous file handle at an offset. Reading past
// the end is io.EOF; any other failure wraps errUnreadable.
type heldFile windows.Handle

func (h heldFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	var done uint32
	at := windows.Overlapped{Offset: uint32(off), OffsetHigh: uint32(off >> 32)}
	err := windows.ReadFile(windows.Handle(h), p, &done, &at)
	if err == windows.ERROR_HANDLE_EOF || err == nil && int(done) < len(p) {
		return int(done), io.EOF
	}
	if err != nil {
		return int(done), fmt.Errorf("%w: %w", errUnreadable, err)
	}
	return int(done), nil
}

// Bounds of the version resource reader. A version resource is one
// VS_VERSIONINFO block, whose length is a 16-bit count of bytes.
const (
	maxHeaderOffset     = 1 << 20
	maxSections         = 96
	maxResourceEntries  = 4096
	maxVersionResource  = 0xffff
	maxOptionalHeader   = 0x1000
	resourceTypeVersion = 16
	resourceDirectory   = 2
)

var errNoVersion = errors.New("no version resource")

// readVersionResource finds the RT_VERSION resource in a PE image's own
// resource section and returns its FileDescription and OriginalFilename. It
// reads only the headers, the section table, the resource directory entries
// it walks and the version resource itself, each bounded.
func readVersionResource(r io.ReaderAt) (imageVersion, error) {
	img, err := readImageLayout(r)
	if err != nil {
		return imageVersion{}, err
	}
	if img.resourceRVA == 0 {
		return imageVersion{}, errNoVersion
	}
	types, err := img.directory(img.resourceRVA)
	if err != nil {
		return imageVersion{}, err
	}
	names, err := img.subdirectory(types, func(e resourceEntry) bool { return !e.named && e.id == resourceTypeVersion })
	if err != nil {
		return imageVersion{}, err
	}
	languages, err := img.subdirectory(names, func(e resourceEntry) bool { return true })
	if err != nil {
		return imageVersion{}, err
	}
	data, err := img.leaf(languages)
	if err != nil {
		return imageVersion{}, err
	}
	return parseVersionInfo(data)
}

type imageSection struct {
	virtualAddress, virtualSize, rawSize, rawOffset uint32
}

type imageLayout struct {
	r           io.ReaderAt
	sections    []imageSection
	resourceRVA uint32
}

func readAt(r io.ReaderAt, off int64, n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := r.ReadAt(buf, off); err != nil {
		return nil, err
	}
	return buf, nil
}

// readImageLayout reads the DOS and PE headers, the resource data directory
// entry and the section table.
func readImageLayout(r io.ReaderAt) (imageLayout, error) {
	dos, err := readAt(r, 0, 64)
	if err != nil {
		return imageLayout{}, err
	}
	if dos[0] != 'M' || dos[1] != 'Z' {
		return imageLayout{}, errors.New("not a PE image")
	}
	peOffset := binary.LittleEndian.Uint32(dos[0x3c:])
	if peOffset > maxHeaderOffset {
		return imageLayout{}, errors.New("not a PE image")
	}
	head, err := readAt(r, int64(peOffset), 24)
	if err != nil {
		return imageLayout{}, err
	}
	if string(head[:4]) != "PE\x00\x00" {
		return imageLayout{}, errors.New("not a PE image")
	}
	sectionCount := int(binary.LittleEndian.Uint16(head[6:]))
	optionalSize := int(binary.LittleEndian.Uint16(head[20:]))
	if sectionCount > maxSections || optionalSize > maxOptionalHeader || optionalSize < 2 {
		return imageLayout{}, errors.New("unexpected PE header")
	}
	optional, err := readAt(r, int64(peOffset)+24, optionalSize)
	if err != nil {
		return imageLayout{}, err
	}
	var countAt, directoriesAt int
	switch binary.LittleEndian.Uint16(optional) {
	case 0x10b:
		countAt, directoriesAt = 92, 96
	case 0x20b:
		countAt, directoriesAt = 108, 112
	default:
		return imageLayout{}, errors.New("unexpected PE optional header")
	}
	img := imageLayout{r: r}
	entry := directoriesAt + resourceDirectory*8
	if countAt+4 <= optionalSize && binary.LittleEndian.Uint32(optional[countAt:]) > resourceDirectory && entry+8 <= optionalSize {
		img.resourceRVA = binary.LittleEndian.Uint32(optional[entry:])
	}
	table, err := readAt(r, int64(peOffset)+24+int64(optionalSize), sectionCount*40)
	if err != nil {
		return imageLayout{}, err
	}
	for i := range sectionCount {
		s := table[i*40:]
		img.sections = append(img.sections, imageSection{
			virtualSize:    binary.LittleEndian.Uint32(s[8:]),
			virtualAddress: binary.LittleEndian.Uint32(s[12:]),
			rawSize:        binary.LittleEndian.Uint32(s[16:]),
			rawOffset:      binary.LittleEndian.Uint32(s[20:]),
		})
	}
	return img, nil
}

// read reads n bytes at an image RVA from the file bytes of the section that
// holds them all.
func (img imageLayout) read(rva uint32, n int) ([]byte, error) {
	end := uint64(rva) + uint64(n)
	for _, s := range img.sections {
		if rva >= s.virtualAddress && end <= uint64(s.virtualAddress)+uint64(s.rawSize) {
			return readAt(img.r, int64(s.rawOffset)+int64(rva-s.virtualAddress), n)
		}
	}
	return nil, fmt.Errorf("RVA %#x is not in the file", rva)
}

type resourceEntry struct {
	named  bool
	id     uint32
	offset uint32 // from the start of the resource section
	subdir bool
}

func (img imageLayout) directory(rva uint32) ([]resourceEntry, error) {
	head, err := img.read(rva, 16)
	if err != nil {
		return nil, err
	}
	count := int(binary.LittleEndian.Uint16(head[12:])) + int(binary.LittleEndian.Uint16(head[14:]))
	if count == 0 || count > maxResourceEntries {
		return nil, errNoVersion
	}
	raw, err := img.read(rva+16, count*8)
	if err != nil {
		return nil, err
	}
	entries := make([]resourceEntry, count)
	for i := range entries {
		name := binary.LittleEndian.Uint32(raw[i*8:])
		offset := binary.LittleEndian.Uint32(raw[i*8+4:])
		entries[i] = resourceEntry{named: name&0x80000000 != 0, id: name &^ 0x80000000,
			offset: offset &^ 0x80000000, subdir: offset&0x80000000 != 0}
	}
	return entries, nil
}

// subdirectory opens the first entry that matches and names a directory.
func (img imageLayout) subdirectory(entries []resourceEntry, match func(resourceEntry) bool) ([]resourceEntry, error) {
	for _, e := range entries {
		if e.subdir && match(e) {
			return img.directory(img.resourceRVA + e.offset)
		}
	}
	return nil, errNoVersion
}

// leaf reads the data of the language entry: the language-neutral one when
// present, the first otherwise. The image carries its own resource; a
// language resource file (.mui) is a separate file and is not consulted.
func (img imageLayout) leaf(languages []resourceEntry) ([]byte, error) {
	chosen := -1
	for i, e := range languages {
		if e.subdir {
			continue
		}
		if chosen < 0 || !e.named && e.id == 0 {
			chosen = i
		}
	}
	if chosen < 0 {
		return nil, errNoVersion
	}
	entry, err := img.read(img.resourceRVA+languages[chosen].offset, 16)
	if err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint32(entry[4:])
	if size < 6 || size > maxVersionResource {
		return nil, errNoVersion
	}
	return img.read(binary.LittleEndian.Uint32(entry), int(size))
}

// versionBlock is one node of a VS_VERSIONINFO tree: its key, the bytes of
// its value, and the span of its children within the resource.
type versionBlock struct {
	key           string
	value         []byte
	children, end int
}

func align4(n int) int { return (n + 3) &^ 3 }

// versionBlockAt parses the block at start. Offsets are relative to the start
// of the resource, the origin of the format's 32-bit alignment.
func versionBlockAt(data []byte, start, limit int) (versionBlock, bool) {
	if start+6 > limit {
		return versionBlock{}, false
	}
	length := int(binary.LittleEndian.Uint16(data[start:]))
	valueLength := int(binary.LittleEndian.Uint16(data[start+2:]))
	text := binary.LittleEndian.Uint16(data[start+4:]) == 1
	end := start + length
	if length < 6 || end > limit {
		return versionBlock{}, false
	}
	key, pos, ok := utf16z(data, start+6, end)
	if !ok {
		return versionBlock{}, false
	}
	pos = align4(pos)
	if text {
		valueLength *= 2
	}
	valueEnd := min(pos+valueLength, end)
	if pos > end {
		pos, valueEnd = end, end
	}
	return versionBlock{key: key, value: data[pos:valueEnd], children: align4(valueEnd), end: end}, true
}

// childBlocks returns the children of b in order.
func childBlocks(data []byte, b versionBlock) []versionBlock {
	var out []versionBlock
	for at := b.children; at+6 <= b.end; {
		child, ok := versionBlockAt(data, at, b.end)
		if !ok {
			break
		}
		out = append(out, child)
		at = align4(child.end)
	}
	return out
}

// utf16z decodes a NUL-terminated UTF-16LE string at start and returns the
// offset after its terminator.
func utf16z(data []byte, start, limit int) (string, int, bool) {
	var units []uint16
	for at := start; at+2 <= limit; at += 2 {
		u := binary.LittleEndian.Uint16(data[at:])
		if u == 0 {
			return string(utf16.Decode(units)), at + 2, true
		}
		units = append(units, u)
	}
	return "", 0, false
}

// textValue decodes a String block's value up to its first NUL.
func textValue(value []byte) string {
	units := make([]uint16, 0, len(value)/2)
	for at := 0; at+2 <= len(value); at += 2 {
		u := binary.LittleEndian.Uint16(value[at:])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return strings.TrimSpace(string(utf16.Decode(units)))
}

// parseVersionInfo reads FileDescription and OriginalFilename out of one
// string table of a VS_VERSIONINFO resource: the table its first
// VarFileInfo\Translation entry names, or the first table when none matches.
// Both come from the same table.
func parseVersionInfo(data []byte) (imageVersion, error) {
	root, ok := versionBlockAt(data, 0, len(data))
	if !ok || root.key != "VS_VERSION_INFO" {
		return imageVersion{}, errNoVersion
	}
	var tables []versionBlock
	translation := ""
	for _, child := range childBlocks(data, root) {
		switch child.key {
		case "StringFileInfo":
			tables = append(tables, childBlocks(data, child)...)
		case "VarFileInfo":
			for _, v := range childBlocks(data, child) {
				if v.key == "Translation" && len(v.value) >= 4 && translation == "" {
					translation = fmt.Sprintf("%04x%04x", binary.LittleEndian.Uint16(v.value), binary.LittleEndian.Uint16(v.value[2:]))
				}
			}
		}
	}
	if len(tables) == 0 {
		return imageVersion{}, errNoVersion
	}
	table := tables[0]
	for _, t := range tables {
		if strings.EqualFold(t.key, translation) {
			table = t
			break
		}
	}
	var version imageVersion
	for _, s := range childBlocks(data, table) {
		switch s.key {
		case "FileDescription":
			version.description = textValue(s.value)
		case "OriginalFilename":
			version.originalName = textValue(s.value)
		}
	}
	return version, nil
}
