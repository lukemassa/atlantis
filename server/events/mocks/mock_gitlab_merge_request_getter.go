// Code generated by pegomock. DO NOT EDIT.
// Source: github.com/runatlantis/atlantis/server/events (interfaces: GitlabMergeRequestGetter)

package mocks

import (
	pegomock "github.com/petergtz/pegomock/v4"
	logging "github.com/runatlantis/atlantis/server/logging"
	client_go "gitlab.com/gitlab-org/api/client-go"
	"reflect"
	"time"
)

type MockGitlabMergeRequestGetter struct {
	fail func(message string, callerSkip ...int)
}

func NewMockGitlabMergeRequestGetter(options ...pegomock.Option) *MockGitlabMergeRequestGetter {
	mock := &MockGitlabMergeRequestGetter{}
	for _, option := range options {
		option.Apply(mock)
	}
	return mock
}

func (mock *MockGitlabMergeRequestGetter) SetFailHandler(fh pegomock.FailHandler) { mock.fail = fh }
func (mock *MockGitlabMergeRequestGetter) FailHandler() pegomock.FailHandler      { return mock.fail }

func (mock *MockGitlabMergeRequestGetter) GetMergeRequest(logger logging.SimpleLogging, repoFullName string, pullNum int) (*client_go.MergeRequest, error) {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockGitlabMergeRequestGetter().")
	}
	_params := []pegomock.Param{logger, repoFullName, pullNum}
	_result := pegomock.GetGenericMockFrom(mock).Invoke("GetMergeRequest", _params, []reflect.Type{reflect.TypeOf((**client_go.MergeRequest)(nil)).Elem(), reflect.TypeOf((*error)(nil)).Elem()})
	var _ret0 *client_go.MergeRequest
	var _ret1 error
	if len(_result) != 0 {
		if _result[0] != nil {
			_ret0 = _result[0].(*client_go.MergeRequest)
		}
		if _result[1] != nil {
			_ret1 = _result[1].(error)
		}
	}
	return _ret0, _ret1
}

func (mock *MockGitlabMergeRequestGetter) VerifyWasCalledOnce() *VerifierMockGitlabMergeRequestGetter {
	return &VerifierMockGitlabMergeRequestGetter{
		mock:                   mock,
		invocationCountMatcher: pegomock.Times(1),
	}
}

func (mock *MockGitlabMergeRequestGetter) VerifyWasCalled(invocationCountMatcher pegomock.InvocationCountMatcher) *VerifierMockGitlabMergeRequestGetter {
	return &VerifierMockGitlabMergeRequestGetter{
		mock:                   mock,
		invocationCountMatcher: invocationCountMatcher,
	}
}

func (mock *MockGitlabMergeRequestGetter) VerifyWasCalledInOrder(invocationCountMatcher pegomock.InvocationCountMatcher, inOrderContext *pegomock.InOrderContext) *VerifierMockGitlabMergeRequestGetter {
	return &VerifierMockGitlabMergeRequestGetter{
		mock:                   mock,
		invocationCountMatcher: invocationCountMatcher,
		inOrderContext:         inOrderContext,
	}
}

func (mock *MockGitlabMergeRequestGetter) VerifyWasCalledEventually(invocationCountMatcher pegomock.InvocationCountMatcher, timeout time.Duration) *VerifierMockGitlabMergeRequestGetter {
	return &VerifierMockGitlabMergeRequestGetter{
		mock:                   mock,
		invocationCountMatcher: invocationCountMatcher,
		timeout:                timeout,
	}
}

type VerifierMockGitlabMergeRequestGetter struct {
	mock                   *MockGitlabMergeRequestGetter
	invocationCountMatcher pegomock.InvocationCountMatcher
	inOrderContext         *pegomock.InOrderContext
	timeout                time.Duration
}

func (verifier *VerifierMockGitlabMergeRequestGetter) GetMergeRequest(logger logging.SimpleLogging, repoFullName string, pullNum int) *MockGitlabMergeRequestGetter_GetMergeRequest_OngoingVerification {
	_params := []pegomock.Param{logger, repoFullName, pullNum}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "GetMergeRequest", _params, verifier.timeout)
	return &MockGitlabMergeRequestGetter_GetMergeRequest_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockGitlabMergeRequestGetter_GetMergeRequest_OngoingVerification struct {
	mock              *MockGitlabMergeRequestGetter
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockGitlabMergeRequestGetter_GetMergeRequest_OngoingVerification) GetCapturedArguments() (logging.SimpleLogging, string, int) {
	logger, repoFullName, pullNum := c.GetAllCapturedArguments()
	return logger[len(logger)-1], repoFullName[len(repoFullName)-1], pullNum[len(pullNum)-1]
}

func (c *MockGitlabMergeRequestGetter_GetMergeRequest_OngoingVerification) GetAllCapturedArguments() (_param0 []logging.SimpleLogging, _param1 []string, _param2 []int) {
	_params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(_params) > 0 {
		if len(_params) > 0 {
			_param0 = make([]logging.SimpleLogging, len(c.methodInvocations))
			for u, param := range _params[0] {
				_param0[u] = param.(logging.SimpleLogging)
			}
		}
		if len(_params) > 1 {
			_param1 = make([]string, len(c.methodInvocations))
			for u, param := range _params[1] {
				_param1[u] = param.(string)
			}
		}
		if len(_params) > 2 {
			_param2 = make([]int, len(c.methodInvocations))
			for u, param := range _params[2] {
				_param2[u] = param.(int)
			}
		}
	}
	return
}
