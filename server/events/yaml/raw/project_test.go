package raw_test

import (
	"testing"

	"github.com/go-ozzo/ozzo-validation"
	"github.com/runatlantis/atlantis/server/events/yaml/raw"
	"github.com/runatlantis/atlantis/server/events/yaml/valid"
	. "github.com/runatlantis/atlantis/testing"
	"gopkg.in/yaml.v2"
)

func TestProject_UnmarshalYAML(t *testing.T) {
	cases := []struct {
		description string
		input       string
		exp         raw.Project
	}{
		{
			description: "omit unset fields",
			input:       "",
			exp: raw.Project{
				Dir:               nil,
				Workspace:         nil,
				Workflow:          nil,
				TerraformVersion:  nil,
				Autoplan:          nil,
				ApplyRequirements: nil,
			},
		},
		{
			description: "all fields set",
			input: `
dir: mydir
workspace: workspace
workflow: workflow
terraform_version: v0.11.0
autoplan:
  when_modified: []
  enabled: false
apply_requirements:
- mergeable`,
			exp: raw.Project{
				Dir:              String("mydir"),
				Workspace:        String("workspace"),
				Workflow:         String("workflow"),
				TerraformVersion: String("v0.11.0"),
				Autoplan: &raw.Autoplan{
					WhenModified: []string{},
					Enabled:      Bool(false),
				},
				ApplyRequirements: []string{"mergeable"},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			var p raw.Project
			err := yaml.UnmarshalStrict([]byte(c.input), &p)
			Ok(t, err)
			Equals(t, c.exp, p)
		})
	}
}

func TestProject_Validate(t *testing.T) {
	cases := []struct {
		description string
		input       raw.Project
		expErr      string
	}{
		{
			description: "minimal fields",
			input: raw.Project{
				Dir: String("."),
			},
			expErr: "",
		},
		{
			description: "dir empty",
			input: raw.Project{
				Dir: nil,
			},
			expErr: "dir: cannot be blank.",
		},
		{
			description: "dir with ..",
			input: raw.Project{
				Dir: String("../mydir"),
			},
			expErr: "dir: cannot contain '..'.",
		},
		{
			description: "apply reqs with unsupported",
			input: raw.Project{
				Dir:               String("."),
				ApplyRequirements: []string{"unsupported"},
			},
			expErr: "apply_requirements: \"unsupported\" not supported, only approved is supported.",
		},
		{
			description: "apply reqs with valid",
			input: raw.Project{
				Dir:               String("."),
				ApplyRequirements: []string{"approved"},
			},
			expErr: "",
		},
	}
	validation.ErrorTag = "yaml"
	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			err := c.input.Validate()
			if c.expErr == "" {
				Ok(t, err)
			} else {
				ErrEquals(t, c.expErr, err)
			}
		})
	}
}

func TestProject_ToValid(t *testing.T) {
	cases := []struct {
		description string
		input       raw.Project
		exp         valid.Project
	}{
		{
			description: "minimal values",
			input: raw.Project{
				Dir: String("."),
			},
			exp: valid.Project{
				Dir:              ".",
				Workspace:        "default",
				Workflow:         nil,
				TerraformVersion: nil,
				Autoplan: valid.Autoplan{
					WhenModified: []string{"**/*.tf"},
					Enabled:      true,
				},
				ApplyRequirements: nil,
			},
		},
		{
			description: "all set",
			input: raw.Project{
				Dir:              String("."),
				Workspace:        String("myworkspace"),
				Workflow:         String("myworkflow"),
				TerraformVersion: String("v0.11.0"),
				Autoplan: &raw.Autoplan{
					WhenModified: []string{"hi"},
					Enabled:      Bool(false),
				},
				ApplyRequirements: []string{"approved"},
			},
			exp: valid.Project{
				Dir:              ".",
				Workspace:        "myworkspace",
				Workflow:         String("myworkflow"),
				TerraformVersion: String("v0.11.0"),
				Autoplan: valid.Autoplan{
					WhenModified: []string{"hi"},
					Enabled:      false,
				},
				ApplyRequirements: []string{"approved"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			Equals(t, c.exp, c.input.ToValid())
		})
	}
}
