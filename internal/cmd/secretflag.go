package cmd

import "github.com/spf13/pflag"

// hideSecretFlagDefaults blanks the displayed default of flags whose value
// is seeded from an environment variable carrying a credential (#2595).
//
// cobra/pflag render a flag's default in usage and --help output, and cobra
// prints usage whenever a command returns an error — so binding
// os.Getenv("CONTAINARIUM_TOKEN") as the default wrote the full JWT to the
// terminal (and to CI logs) on any failed command. Only the displayed
// default (DefValue) is cleared: the bound variable keeps the env value, so
// flag > env precedence is unchanged.
func hideSecretFlagDefaults(fs *pflag.FlagSet, names ...string) {
	for _, n := range names {
		if f := fs.Lookup(n); f != nil {
			f.DefValue = ""
		}
	}
}
