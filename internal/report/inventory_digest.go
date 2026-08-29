package report

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"sort"
	"strings"
	"unicode/utf8"
)

const inventoryDigestDomain = "plug-prejudice/target-inventory-root/v1"

// InventoryRootDigest binds the retained filesystem observation, not later
// analysis. Records are sorted by target-relative path and every variable
// field is unsigned-64-bit length-prefixed, so no field boundary is inferred
// from hostile text.
func InventoryRootDigest(files []File) (string, error) {
	ordered := append([]File(nil), files...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	digest := sha256.New()
	writeDigestString(digest, inventoryDigestDomain)
	writeDigestUint64(digest, uint64(len(ordered)))
	for _, file := range ordered {
		if file.Size < 0 {
			return "", errors.New("inventory digest cannot encode a negative file size")
		}
		for _, value := range []string{file.Path, file.Kind, file.Mode, file.SHA256, file.LinkTarget, file.SkipReason} {
			if !utf8.ValidString(value) {
				return "", errors.New("inventory digest cannot encode invalid UTF-8")
			}
			if strings.ContainsRune(value, '\x00') {
				return "", errors.New("inventory digest fields cannot contain NUL")
			}
		}
		writeDigestString(digest, file.Path)
		writeDigestString(digest, file.Kind)
		writeDigestString(digest, file.Mode)
		writeDigestUint64(digest, uint64(file.Size))
		writeDigestString(digest, file.SHA256)
		writeDigestString(digest, file.LinkTarget)
		writeDigestString(digest, file.SkipReason)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func writeDigestString(destination hash.Hash, value string) {
	writeDigestUint64(destination, uint64(len(value)))
	_, _ = destination.Write([]byte(value))
}

func writeDigestUint64(destination hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = destination.Write(encoded[:])
}
