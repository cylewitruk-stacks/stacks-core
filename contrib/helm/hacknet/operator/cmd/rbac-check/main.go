// Command rbac-check validates least-privilege Roles from a rendered Hacknet chart.
package main

import (
	"fmt"
	"os"

	"github.com/stacks-network/stacks-core/contrib/helm/hacknet/operator/internal/rbac"
)

func main() {
	if err := rbac.Validate(os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
