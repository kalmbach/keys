package main

import (
	"testing"
	"time"
)

func TestRelativeExpires(t *testing.T) {
	at := func(year int, month time.Month, day int) time.Time {
		return time.Date(year, month, day, 12, 0, 0, 0, time.UTC)
	}

	may15 := at(2026, time.May, 15)
	dec15 := at(2026, time.December, 15)

	tests := []struct {
		name string
		now  time.Time
		t    time.Time
		want string
	}{
		{"already past", may15, may15.Add(-24 * time.Hour), "expires today"},
		{"exactly now", may15, may15, "expires today"},
		{"23 hours away still today", may15, may15.Add(23 * time.Hour), "expires today"},
		{"exactly 24h is tomorrow", may15, may15.Add(24 * time.Hour), "expires tomorrow"},
		{"47h still tomorrow", may15, may15.Add(47 * time.Hour), "expires tomorrow"},
		{"48h flips to 2 days", may15, may15.Add(48 * time.Hour), "expires in 2 days"},

		{"16 days same month", may15, at(2026, time.May, 31), "expires in 16 days"},
		{"26 days next cal month, urgency wins", may15, at(2026, time.June, 10), "expires in 26 days"},
		{"36 days next cal month", may15, at(2026, time.June, 20), "expires next month"},
		{"61 days is 2 months", may15, at(2026, time.July, 15), "expires in 2 months"},
		{"11 cal months", may15, at(2027, time.April, 15), "expires in 11 months"},

		{"exactly 12 cal months is next year", may15, at(2027, time.May, 15), "expires next year"},
		{"19 months still next year", may15, at(2027, time.December, 31), "expires next year"},
		{"20 months flips to 2 years", may15, at(2028, time.January, 1), "expires in 2 years"},
		{"5 years", may15, at(2031, time.May, 15), "expires in 5 years"},

		{"cross-year next month", dec15, at(2027, time.January, 15), "expires next month"},
		{"cross-year same month in days", dec15, at(2026, time.December, 31), "expires in 16 days"},
		{"cross-year 13 cal months reads as 2 years", dec15, at(2028, time.January, 15), "expires in 2 years"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := relativeExpires(tc.t, tc.now)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExpiringSoon(t *testing.T) {
	at := func(year int, month time.Month, day int) time.Time {
		return time.Date(year, month, day, 12, 0, 0, 0, time.UTC)
	}

	now := at(2026, time.May, 15)

	tests := []struct {
		name string
		t    time.Time
		want bool
	}{
		{"already past", now.Add(-24 * time.Hour), true},
		{"today", now, true},
		{"tomorrow", now.Add(36 * time.Hour), true},
		{"in 15 days", now.Add(15 * 24 * time.Hour), true},
		{"in 30 days exactly", now.Add(30 * 24 * time.Hour), true},
		{"in 31 days", now.Add(31 * 24 * time.Hour), false},
		{"in 2 months", at(2026, time.July, 15), false},
		{"in 1 year", at(2027, time.May, 15), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := expiringSoon(tc.t, now)
			if got != tc.want {
				t.Errorf("expiringSoon(%s) = %v, want %v", tc.t.Format(time.DateOnly), got, tc.want)
			}
		})
	}
}
