// Code generated by pegomock. DO NOT EDIT.
package matchers

import (
	"reflect"

	"github.com/petergtz/pegomock"

	slack "github.com/slack-go/slack"
)

func AnySlackPostMessageParameters() slack.PostMessageParameters {
	pegomock.RegisterMatcher(pegomock.NewAnyMatcher(reflect.TypeOf((*(slack.PostMessageParameters))(nil)).Elem()))
	var nullValue slack.PostMessageParameters
	return nullValue
}

func EqSlackPostMessageParameters(value slack.PostMessageParameters) slack.PostMessageParameters {
	pegomock.RegisterMatcher(&pegomock.EqMatcher{Value: value})
	var nullValue slack.PostMessageParameters
	return nullValue
}

func NotEqSlackPostMessageParameters(value slack.PostMessageParameters) slack.PostMessageParameters {
	pegomock.RegisterMatcher(&pegomock.NotEqMatcher{Value: value})
	var nullValue slack.PostMessageParameters
	return nullValue
}

func SlackPostMessageParametersThat(matcher pegomock.ArgumentMatcher) slack.PostMessageParameters {
	pegomock.RegisterMatcher(matcher)
	var nullValue slack.PostMessageParameters
	return nullValue
}
