// Package fakealias declares aliases of configured safe types
// in a package which is not configured itself.
package fakealias

import "fakesecrecy"

// Secret is a safe type reachable only through this alias.
type Secret = fakesecrecy.Secret[string]
