package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// Vault implements AES-256-GCM Envelope Encryption for Boundary 2 upstream provider API keys.
// Each credential record receives its own randomly generated 256-bit Data Encryption Key (DEK),
// and the DEK is encrypted using the Gateway's 256-bit Master Key Encryption Key (KEK).
type Vault struct {
	kek []byte
}

func NewVault(masterKey string) (*Vault, error) {
	if len(masterKey) < 32 {
		return nil, fmt.Errorf("master encryption key must be at least 32 characters")
	}
	var kek []byte
	if decoded, err := hex.DecodeString(masterKey); err == nil && len(decoded) == 32 {
		kek = decoded
	} else {
		sum := sha256.Sum256([]byte(masterKey))
		kek = sum[:]
	}
	return &Vault{kek: kek}, nil
}

// EncryptCredential encrypts a plaintext provider API key into cred's envelope fields and clears DecryptedAPIKey.
func (v *Vault) EncryptCredential(cred *domain.ProviderCredential, rawAPIKey string) error {
	rawAPIKey = strings.TrimSpace(rawAPIKey)
	// 1. Generate random 32-byte DEK
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return fmt.Errorf("generate DEK: %w", err)
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	// 2. Encrypt plaintext API key with DEK
	encKey, dataNonce, err := aesGCMEncrypt(dek, []byte(rawAPIKey))
	if err != nil {
		return fmt.Errorf("encrypt api key with DEK: %w", err)
	}

	// 3. Encrypt DEK with Master KEK
	encDEK, dekNonce, err := aesGCMEncrypt(v.kek, dek)
	if err != nil {
		return fmt.Errorf("encrypt DEK with KEK: %w", err)
	}

	cred.EncryptedAPIKey = encKey
	cred.DataNonce = dataNonce
	cred.EncryptedDEK = encDEK
	cred.DEKNonce = dekNonce
	cred.DecryptedAPIKey = ""
	if cred.KeyVersion <= 0 {
		cred.KeyVersion = 1
	}
	return nil
}

// RotateCredential re-encrypts a provider credential with a fresh 256-bit DEK, increments KeyVersion, and sets LastRotatedAt.
func (v *Vault) RotateCredential(cred *domain.ProviderCredential, newAPIKey string) error {
	if cred == nil {
		return fmt.Errorf("credential cannot be nil")
	}
	if err := v.EncryptCredential(cred, newAPIKey); err != nil {
		return err
	}
	cred.KeyVersion++
	now := time.Now().UTC()
	cred.LastRotatedAt = &now
	return nil
}

// ReWrapCredential re-encrypts the DEK using a new Vault's KEK, leaving data ciphertext unchanged.
// It returns a newly rotated credential snapshot for atomic substitution, achieving zero-downtime,
// zero-race master key rotation under high-load production.
func (v *Vault) ReWrapCredential(cred *domain.ProviderCredential, newVault *Vault) (*domain.ProviderCredential, error) {
	if cred == nil || newVault == nil {
		return nil, fmt.Errorf("credential and newVault cannot be nil")
	}
	dek, err := aesGCMDecrypt(v.kek, cred.DEKNonce, cred.EncryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("decrypt DEK with old KEK: %w", err)
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	newEncDEK, newDEKNonce, err := aesGCMEncrypt(newVault.kek, dek)
	if err != nil {
		return nil, fmt.Errorf("encrypt DEK with new KEK: %w", err)
	}

	rotated := *cred
	rotated.EncryptedDEK = newEncDEK
	rotated.DEKNonce = newDEKNonce
	rotated.KeyVersion++
	now := time.Now().UTC()
	rotated.LastRotatedAt = &now
	return &rotated, nil
}

// DecryptCredential decrypts the envelope-encrypted API key in cred and returns the plaintext string.
func (v *Vault) DecryptCredential(cred *domain.ProviderCredential) (string, error) {
	if cred == nil {
		return "", nil
	}
	if cred.DecryptedAPIKey != "" {
		return cred.DecryptedAPIKey, nil
	}
	if len(cred.EncryptedAPIKey) == 0 || len(cred.EncryptedDEK) == 0 {
		return "", nil
	}

	dek, err := aesGCMDecrypt(v.kek, cred.DEKNonce, cred.EncryptedDEK)
	if err != nil {
		return "", fmt.Errorf("decrypt DEK: %w", err)
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	rawKey, err := aesGCMDecrypt(dek, cred.DataNonce, cred.EncryptedAPIKey)
	if err != nil {
		return "", fmt.Errorf("decrypt API key: %w", err)
	}
	return string(rawKey), nil
}

// EncryptString provides generic AES-256-GCM envelope encryption for any secret string (MCP, A2A, BYOK).
func (v *Vault) EncryptString(plaintext string) (string, string, error) {
	plaintext = strings.TrimSpace(plaintext)
	if plaintext == "" {
		return "", "", nil
	}

	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return "", "", fmt.Errorf("generate DEK: %w", err)
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	encData, dataNonce, err := aesGCMEncrypt(dek, []byte(plaintext))
	if err != nil {
		return "", "", fmt.Errorf("encrypt data: %w", err)
	}
	encDEK, dekNonce, err := aesGCMEncrypt(v.kek, dek)
	if err != nil {
		return "", "", fmt.Errorf("encrypt DEK: %w", err)
	}

	packedData := append(dataNonce, encData...)
	packedDEK := append(dekNonce, encDEK...)

	return hex.EncodeToString(packedData), hex.EncodeToString(packedDEK), nil
}

// DecryptString decrypts generic AES-256-GCM envelope-encrypted secrets.
func (v *Vault) DecryptString(encHex, dekHex string) (string, error) {
	encHex = strings.TrimSpace(encHex)
	dekHex = strings.TrimSpace(dekHex)
	if encHex == "" || dekHex == "" {
		return "", nil
	}

	packedData, err := hex.DecodeString(encHex)
	if err != nil || len(packedData) < 12 {
		return "", fmt.Errorf("invalid packed data hex: %w", err)
	}
	packedDEK, err := hex.DecodeString(dekHex)
	if err != nil || len(packedDEK) < 12 {
		return "", fmt.Errorf("invalid packed DEK hex: %w", err)
	}

	dekNonce := packedDEK[:12]
	encDEK := packedDEK[12:]
	dek, err := aesGCMDecrypt(v.kek, dekNonce, encDEK)
	if err != nil {
		return "", fmt.Errorf("decrypt DEK: %w", err)
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	dataNonce := packedData[:12]
	encData := packedData[12:]
	plainBytes, err := aesGCMDecrypt(dek, dataNonce, encData)
	if err != nil {
		return "", fmt.Errorf("decrypt data: %w", err)
	}

	return string(plainBytes), nil
}

func aesGCMEncrypt(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func aesGCMDecrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}
