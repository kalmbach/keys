package main

import (
	"fmt"
	"time"
)

func relativeExpires(t, now time.Time) string {
	days := int(t.Sub(now).Hours() / 24)

	if days <= 0 {
		return "expires today"
	}

	if days == 1 {
		return "expires tomorrow"
	}

	monthsDiff := (t.Year()-now.Year())*12 + int(t.Month()) - int(now.Month())

	if days < 30 || monthsDiff <= 0 {
		return fmt.Sprintf("expires in %d days", days)
	}

	if monthsDiff == 1 {
		return "expires next month"
	}

	if monthsDiff < 12 {
		return fmt.Sprintf("expires in %d months", monthsDiff)
	}

	yearsDiff := t.Year() - now.Year()

	if yearsDiff == 1 {
		return "expires next year"
	}

	return fmt.Sprintf("expires in %d years", yearsDiff)
}
