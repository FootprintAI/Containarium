package cmd

import (
	"os"

	"github.com/spf13/pflag"
)

// secretEnvFlag registers a string flag whose value falls back to the
// environment variable env, without ever advertising that value: pflag renders
// a flag's DefValue in usage and --help, so an env-derived default would print
// the secret in plaintext whenever cobra shows usage (#2595). The flag's
// effective value is still the env value; only its displayed default is blank.
func secretEnvFlag(fs *pflag.FlagSet, p *string, name, env, usage string) {
	fs.StringVar(p, name, os.Getenv(env), usage)
	fs.Lookup(name).DefValue = ""
}
