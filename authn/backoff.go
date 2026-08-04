package authn

import "time"

// Exponential backoff against credential guessing (ASVS 6.1): reject-until windows, not
// server-side sleeps — a sleeping goroutine per attacker request is a DoS lever handed to the
// attacker, where a rejection costs nothing to hold.
//
// Hard lockout is deliberately absent: anyone who knows a victim's email could lock them out
// at will. A capped exponential window costs an attacker everything and a fat-fingered user
// almost nothing, and it self-recovers.
const (
	// userFreeFailures @notice Failures before the per-account curve starts. One free retry:
	// a typo'd password should not cost a wait.
	userFreeFailures = 1

	// ipFreeFailures @notice Failures before the per-address curve starts — higher, because an
	// office NAT is many people, and because this counter exists to catch spraying (one
	// attempt against many accounts), which the per-account counter structurally cannot see.
	ipFreeFailures = 10

	// maxDelay @notice The cap of both curves.
	maxDelay = 30 * time.Second

	// suspiciousFailures @notice Prior failures at which a successful login triggers a
	// notification — the "many failures, then a success" pattern of a guessed password.
	suspiciousFailures = 3
)

// delayFor @notice The wait a key must observe after its nth failure: 0 while within the free
// allowance, then 1s, 2s, 4s … capped at maxDelay.
//
// @param scope    "user" or "ip", selecting the free allowance
// @param failures the recorded failure count
// @return time.Duration the reject-until window measured from the last failure
func delayFor(scope string, failures int) time.Duration {
	free := userFreeFailures
	if scope == scopeIP {
		free = ipFreeFailures
	}
	over := failures - free
	if over <= 0 {
		return 0
	}
	if over > 5 { // 1<<5 s would already exceed the 30s cap
		return maxDelay
	}
	d := time.Second << (over - 1)
	if d > maxDelay {
		return maxDelay
	}
	return d
}
