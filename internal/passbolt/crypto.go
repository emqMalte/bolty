package passbolt

import (
	"encoding/json"
	"errors"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

type PGPService struct{}

func NewPGPService() PGPService {
	return PGPService{}
}

func (PGPService) UnlockPrivateKey(armoredPrivateKey, passphrase string) (*crypto.Key, error) {
	if armoredPrivateKey == "" {
		return nil, errors.New("private key is required")
	}
	key, err := crypto.NewPrivateKeyFromArmored(armoredPrivateKey, []byte(passphrase))
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (PGPService) PublicKey(armoredPublicKey string) (*crypto.Key, error) {
	if armoredPublicKey == "" {
		return nil, errors.New("public key is required")
	}
	return crypto.NewKeyFromArmored(armoredPublicKey)
}

func (p PGPService) EncryptAndSignJSON(value any, recipientPublicKey, signingPrivateKey *crypto.Key) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return p.EncryptAndSign(data, recipientPublicKey, signingPrivateKey)
}

func (PGPService) EncryptAndSign(data []byte, recipientPublicKey, signingPrivateKey *crypto.Key) (string, error) {
	if recipientPublicKey == nil {
		return "", errors.New("recipient public key is required")
	}
	if signingPrivateKey == nil {
		return "", errors.New("signing private key is required")
	}
	signingKey, err := signingPrivateKey.Copy()
	if err != nil {
		return "", err
	}
	pgp := crypto.PGP()
	handle, err := pgp.Encryption().Recipient(recipientPublicKey).SigningKey(signingKey).Utf8().New()
	if err != nil {
		return "", err
	}
	defer handle.ClearPrivateParams()
	msg, err := handle.Encrypt(data)
	if err != nil {
		return "", err
	}
	return msg.Armor()
}

func (PGPService) DecryptArmored(armored string, privateKey *crypto.Key) ([]byte, error) {
	if armored == "" {
		return nil, errors.New("armored message is required")
	}
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}
	decryptionKey, err := privateKey.Copy()
	if err != nil {
		return nil, err
	}
	defer decryptionKey.ClearPrivateParams()

	pgp := crypto.PGP()
	handle, err := pgp.Decryption().
		DecryptionKey(decryptionKey).
		DisableIntendedRecipients().
		New()
	if err != nil {
		return nil, err
	}
	defer handle.ClearPrivateParams()
	result, err := handle.Decrypt([]byte(armored), crypto.Armor)
	if err != nil {
		return nil, wrapPGPError(err)
	}
	return result.Bytes(), nil
}

func (PGPService) DecryptArmoredWithPassword(armored, password string) ([]byte, error) {
	if armored == "" {
		return nil, errors.New("armored message is required")
	}
	pgp := crypto.PGP()
	handle, err := pgp.Decryption().Password([]byte(password)).New()
	if err != nil {
		return nil, err
	}
	result, err := handle.Decrypt([]byte(armored), crypto.Armor)
	if err != nil {
		return nil, wrapPGPError(err)
	}
	return result.Bytes(), nil
}

func (p PGPService) DecryptArmoredJSON(armored string, privateKey *crypto.Key, target any) error {
	data, err := p.DecryptArmored(armored, privateKey)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}
