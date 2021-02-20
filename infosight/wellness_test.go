package infosight

import (
	"fmt"
	"testing"
)

func TestStatus(t *testing.T) {
	c, err := NewClientFromEnvironment(WithTrace(true))
	if err != nil {
		t.Error(err)
		return
	}

	i, err := c.Wellness.GetIssues()
	if err != nil {
		t.Error(err)
		return
	}

	fmt.Printf("%v", i)
}
