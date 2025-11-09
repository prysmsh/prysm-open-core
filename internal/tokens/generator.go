package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// GenerateOrgScopedToken creates a token whose body embeds the organization ID.
// The returned token is prefixed with "tkn_" and the accompanying hash is the
// hex-encoded SHA-256 digest of the full token value.
func GenerateOrgScopedToken(orgID uint) (string, string, error) {
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return "", "", fmt.Errorf("generate token entropy: %w", err)
	}

	tokenBody := fmt.Sprintf("org_%d_%s", orgID, hex.EncodeToString(entropy))
	token := "tkn_" + base64.URLEncoding.EncodeToString([]byte(tokenBody))
	sum := sha256.Sum256([]byte(token))

	return token, hex.EncodeToString(sum[:]), nil
}
