package common

import "fmt"

func (p *Process) String() string {
	return fmt.Sprintf("%d/%s", p.Pid, p.Name)
}
