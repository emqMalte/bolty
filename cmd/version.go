package cmd

import "fmt"

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func versionString() string {
	if commit == "unknown" && date == "unknown" {
		return version
	}
	return fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)
}
