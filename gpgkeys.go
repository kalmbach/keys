package main

import (
	"time"

	"github.com/proglottis/gpgme"
)

type UID struct {
	Name    string
	Comment string
	Email   string
}

type Key struct {
	KeyID       string
	Fingerprint string
	PrimaryUID  UID
	Expires     time.Time
	Secret      bool
	Revoked     bool
	Expired     bool
}

func LoadKeys() ([]Key, error) {
	secretFingerprints := map[string]bool{}
	secretKeys, err := gpgme.FindKeys("", true)
	if err != nil {
		return nil, err
	}

	for _, k := range secretKeys {
		if sub := k.SubKeys(); sub != nil {
			secretFingerprints[sub.Fingerprint()] = true
		}
	}

	publicKeys, err := gpgme.FindKeys("", false)
	if err != nil {
		return nil, err
	}

	var keys []Key
	for _, k := range publicKeys {
		if sub := k.SubKeys(); sub != nil {
			uid := k.UserIDs()
			var primary UID

			if uid != nil {
				primary = UID{Name: uid.Name(), Comment: uid.Comment(), Email: uid.Email()}
			}

			keys = append(keys, Key{
				KeyID:       sub.KeyID(),
				Fingerprint: sub.Fingerprint(),
				PrimaryUID:  primary,
				Expires:     sub.Expires(),
				Secret:      secretFingerprints[sub.Fingerprint()],
				Revoked:     k.Revoked(),
				Expired:     k.Expired(),
			})
		}
	}

	return keys, nil
}
