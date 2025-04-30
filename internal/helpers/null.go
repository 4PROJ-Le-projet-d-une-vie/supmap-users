package helpers

import (
	"encoding/json"
)

type NullString struct {
	Set   bool
	Value *string
}

func (ns *NullString) String() string {
	if ns.Value != nil {
		return *ns.Value
	}
	return ""
}

func (ns *NullString) UnmarshalJSON(data []byte) error {
	ns.Set = true
	if string(data) == "null" {
		ns.Value = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	ns.Value = &s
	return nil
}
