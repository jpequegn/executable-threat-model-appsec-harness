package version

const current = "0.1.0"

// String returns the CLI version without depending on build metadata.
func String() string {
	return current
}
