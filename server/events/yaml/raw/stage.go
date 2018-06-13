package raw

import (
	"github.com/go-ozzo/ozzo-validation"
	"github.com/runatlantis/atlantis/server/events/yaml/valid"
)

type Stage struct {
	Steps []Step `yaml:"steps,omitempty"`
}

func (s Stage) Validate() error {
	return validation.ValidateStruct(&s,
		validation.Field(&s.Steps),
	)
}

func (s Stage) ToValid() valid.Stage {
	var validSteps []valid.Step
	for _, s := range s.Steps {
		validSteps = append(validSteps, s.ToValid())
	}
	return valid.Stage{
		Steps: validSteps,
	}
}
