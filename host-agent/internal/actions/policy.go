package actions

import (
	"encoding/json"
	"errors"
	"os"
	"sentinelmesh/host-agent/internal/policy"
)

// ApplyPolicy verifies the control-plane signature before atomically replacing
// the detector's runtime policy file. The original bytes are returned so the
// caller can persist an exact rollback image if desired.
func ApplyPolicy(path, signingKey string, signed policy.Signed) (previous policy.Signed, hadPrevious bool, err error) {
	return applyPolicy(path, signingKey, signed, false)
}

func RollbackPolicy(path, signingKey string, signed policy.Signed) (previous policy.Signed, hadPrevious bool, err error) {
	return applyPolicy(path, signingKey, signed, true)
}

func applyPolicy(path, signingKey string, signed policy.Signed, allowDowngrade bool) (previous policy.Signed, hadPrevious bool, err error) {
	newDoc, verifyErr := policy.Verify(signed, signingKey)
	if verifyErr != nil {
		return previous, false, verifyErr
	}
	if b, readErr := os.ReadFile(path); readErr == nil {
		var old policy.Signed
		if err = json.Unmarshal(b, &old); err != nil {
			return previous, false, err
		}
		oldDoc, verifyErr := policy.Verify(old, signingKey)
		if verifyErr != nil {
			return previous, false, verifyErr
		}
		previous = old
		hadPrevious = true
		if !allowDowngrade && newDoc.Version < oldDoc.Version {
			return previous, hadPrevious, errors.New("policy version must increase for apply")
		}
		if !allowDowngrade && newDoc.Version == oldDoc.Version {
			if previous.Payload == signed.Payload && previous.Signature == signed.Signature {
				// Idempotent replay: the exact same signed policy is already active.
				return previous, hadPrevious, nil
			}
			return previous, hadPrevious, errors.New("policy version collision: same version has different content")
		}
	} else if !os.IsNotExist(readErr) {
		return previous, false, readErr
	}
	if err = policy.WriteAtomic(path, signed, signingKey); err != nil {
		return previous, hadPrevious, err
	}
	return previous, hadPrevious, nil
}

func ReadPolicy(path, signingKey string) (policy.Document, error) {
	d, _, err := policy.Read(path, signingKey)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return d, nil
		}
		return d, err
	}
	return d, nil
}
