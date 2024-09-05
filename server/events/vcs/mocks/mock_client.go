// Code generated by pegomock. DO NOT EDIT.
// Source: github.com/runatlantis/atlantis/server/events/vcs (interfaces: Client)

package mocks

import (
	pegomock "github.com/petergtz/pegomock/v4"
	models "github.com/runatlantis/atlantis/server/events/models"
	logging "github.com/runatlantis/atlantis/server/logging"
	"reflect"
	"time"
)

type MockClient struct {
	fail func(message string, callerSkip ...int)
}

func NewMockClient(options ...pegomock.Option) *MockClient {
	mock := &MockClient{}
	for _, option := range options {
		option.Apply(mock)
	}
	return mock
}

func (mock *MockClient) SetFailHandler(fh pegomock.FailHandler) { mock.fail = fh }
func (mock *MockClient) FailHandler() pegomock.FailHandler      { return mock.fail }

func (mock *MockClient) CreateComment(logger logging.SimpleLogging, repo models.Repo, pullNum int, comment string, command string) error {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockClient().")
	}
	_params := []pegomock.Param{logger, repo, pullNum, comment, command}
	_result := pegomock.GetGenericMockFrom(mock).Invoke("CreateComment", _params, []reflect.Type{reflect.TypeOf((*error)(nil)).Elem()})
	var _ret0 error
	if len(_result) != 0 {
		if _result[0] != nil {
			_ret0 = _result[0].(error)
		}
	}
	return _ret0
}

func (mock *MockClient) DiscardReviews(repo models.Repo, pull models.PullRequest) error {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockClient().")
	}
	_params := []pegomock.Param{repo, pull}
	_result := pegomock.GetGenericMockFrom(mock).Invoke("DiscardReviews", _params, []reflect.Type{reflect.TypeOf((*error)(nil)).Elem()})
	var _ret0 error
	if len(_result) != 0 {
		if _result[0] != nil {
			_ret0 = _result[0].(error)
		}
	}
	return _ret0
}

func (mock *MockClient) GetCloneURL(logger logging.SimpleLogging, VCSHostType models.VCSHostType, repo string) (string, error) {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockClient().")
	}
	_params := []pegomock.Param{logger, VCSHostType, repo}
	_result := pegomock.GetGenericMockFrom(mock).Invoke("GetCloneURL", _params, []reflect.Type{reflect.TypeOf((*string)(nil)).Elem(), reflect.TypeOf((*error)(nil)).Elem()})
	var _ret0 string
	var _ret1 error
	if len(_result) != 0 {
		if _result[0] != nil {
			_ret0 = _result[0].(string)
		}
		if _result[1] != nil {
			_ret1 = _result[1].(error)
		}
	}
	return _ret0, _ret1
}

func (mock *MockClient) GetFileContent(logger logging.SimpleLogging, pull models.PullRequest, fileName string) (bool, []byte, error) {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockClient().")
	}
	_params := []pegomock.Param{logger, pull, fileName}
	_result := pegomock.GetGenericMockFrom(mock).Invoke("GetFileContent", _params, []reflect.Type{reflect.TypeOf((*bool)(nil)).Elem(), reflect.TypeOf((*[]byte)(nil)).Elem(), reflect.TypeOf((*error)(nil)).Elem()})
	var _ret0 bool
	var _ret1 []byte
	var _ret2 error
	if len(_result) != 0 {
		if _result[0] != nil {
			_ret0 = _result[0].(bool)
		}
		if _result[1] != nil {
			_ret1 = _result[1].([]byte)
		}
		if _result[2] != nil {
			_ret2 = _result[2].(error)
		}
	}
	return _ret0, _ret1, _ret2
}

func (mock *MockClient) GetModifiedFiles(logger logging.SimpleLogging, repo models.Repo, pull models.PullRequest) ([]string, error) {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockClient().")
	}
	_params := []pegomock.Param{logger, repo, pull}
	_result := pegomock.GetGenericMockFrom(mock).Invoke("GetModifiedFiles", _params, []reflect.Type{reflect.TypeOf((*[]string)(nil)).Elem(), reflect.TypeOf((*error)(nil)).Elem()})
	var _ret0 []string
	var _ret1 error
	if len(_result) != 0 {
		if _result[0] != nil {
			_ret0 = _result[0].([]string)
		}
		if _result[1] != nil {
			_ret1 = _result[1].(error)
		}
	}
	return _ret0, _ret1
}

func (mock *MockClient) GetPullLabels(logger logging.SimpleLogging, repo models.Repo, pull models.PullRequest) ([]string, error) {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockClient().")
	}
	_params := []pegomock.Param{logger, repo, pull}
	_result := pegomock.GetGenericMockFrom(mock).Invoke("GetPullLabels", _params, []reflect.Type{reflect.TypeOf((*[]string)(nil)).Elem(), reflect.TypeOf((*error)(nil)).Elem()})
	var _ret0 []string
	var _ret1 error
	if len(_result) != 0 {
		if _result[0] != nil {
			_ret0 = _result[0].([]string)
		}
		if _result[1] != nil {
			_ret1 = _result[1].(error)
		}
	}
	return _ret0, _ret1
}

func (mock *MockClient) GetTeamNamesForUser(logger logging.SimpleLogging, repo models.Repo, user models.User) ([]string, error) {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockClient().")
	}
	_params := []pegomock.Param{logger, repo, user}
	_result := pegomock.GetGenericMockFrom(mock).Invoke("GetTeamNamesForUser", _params, []reflect.Type{reflect.TypeOf((*[]string)(nil)).Elem(), reflect.TypeOf((*error)(nil)).Elem()})
	var _ret0 []string
	var _ret1 error
	if len(_result) != 0 {
		if _result[0] != nil {
			_ret0 = _result[0].([]string)
		}
		if _result[1] != nil {
			_ret1 = _result[1].(error)
		}
	}
	return _ret0, _ret1
}

func (mock *MockClient) HidePrevCommandComments(logger logging.SimpleLogging, repo models.Repo, pullNum int, command string, dir string) error {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockClient().")
	}
	_params := []pegomock.Param{logger, repo, pullNum, command, dir}
	_result := pegomock.GetGenericMockFrom(mock).Invoke("HidePrevCommandComments", _params, []reflect.Type{reflect.TypeOf((*error)(nil)).Elem()})
	var _ret0 error
	if len(_result) != 0 {
		if _result[0] != nil {
			_ret0 = _result[0].(error)
		}
	}
	return _ret0
}

func (mock *MockClient) MarkdownPullLink(pull models.PullRequest) (string, error) {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockClient().")
	}
	_params := []pegomock.Param{pull}
	_result := pegomock.GetGenericMockFrom(mock).Invoke("MarkdownPullLink", _params, []reflect.Type{reflect.TypeOf((*string)(nil)).Elem(), reflect.TypeOf((*error)(nil)).Elem()})
	var _ret0 string
	var _ret1 error
	if len(_result) != 0 {
		if _result[0] != nil {
			_ret0 = _result[0].(string)
		}
		if _result[1] != nil {
			_ret1 = _result[1].(error)
		}
	}
	return _ret0, _ret1
}

func (mock *MockClient) MergePull(logger logging.SimpleLogging, pull models.PullRequest, pullOptions models.PullRequestOptions) error {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockClient().")
	}
	_params := []pegomock.Param{logger, pull, pullOptions}
	_result := pegomock.GetGenericMockFrom(mock).Invoke("MergePull", _params, []reflect.Type{reflect.TypeOf((*error)(nil)).Elem()})
	var _ret0 error
	if len(_result) != 0 {
		if _result[0] != nil {
			_ret0 = _result[0].(error)
		}
	}
	return _ret0
}

func (mock *MockClient) PullIsApproved(logger logging.SimpleLogging, repo models.Repo, pull models.PullRequest) (models.ApprovalStatus, error) {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockClient().")
	}
	_params := []pegomock.Param{logger, repo, pull}
	_result := pegomock.GetGenericMockFrom(mock).Invoke("PullIsApproved", _params, []reflect.Type{reflect.TypeOf((*models.ApprovalStatus)(nil)).Elem(), reflect.TypeOf((*error)(nil)).Elem()})
	var _ret0 models.ApprovalStatus
	var _ret1 error
	if len(_result) != 0 {
		if _result[0] != nil {
			_ret0 = _result[0].(models.ApprovalStatus)
		}
		if _result[1] != nil {
			_ret1 = _result[1].(error)
		}
	}
	return _ret0, _ret1
}

func (mock *MockClient) PullIsMergeable(logger logging.SimpleLogging, repo models.Repo, pull models.PullRequest, vcsstatusname string) (bool, error) {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockClient().")
	}
	_params := []pegomock.Param{logger, repo, pull, vcsstatusname}
	_result := pegomock.GetGenericMockFrom(mock).Invoke("PullIsMergeable", _params, []reflect.Type{reflect.TypeOf((*bool)(nil)).Elem(), reflect.TypeOf((*error)(nil)).Elem()})
	var _ret0 bool
	var _ret1 error
	if len(_result) != 0 {
		if _result[0] != nil {
			_ret0 = _result[0].(bool)
		}
		if _result[1] != nil {
			_ret1 = _result[1].(error)
		}
	}
	return _ret0, _ret1
}

func (mock *MockClient) ReactToComment(logger logging.SimpleLogging, repo models.Repo, pullNum int, commentID int64, reaction string) error {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockClient().")
	}
	_params := []pegomock.Param{logger, repo, pullNum, commentID, reaction}
	_result := pegomock.GetGenericMockFrom(mock).Invoke("ReactToComment", _params, []reflect.Type{reflect.TypeOf((*error)(nil)).Elem()})
	var _ret0 error
	if len(_result) != 0 {
		if _result[0] != nil {
			_ret0 = _result[0].(error)
		}
	}
	return _ret0
}

func (mock *MockClient) SupportsSingleFileDownload(repo models.Repo) bool {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockClient().")
	}
	_params := []pegomock.Param{repo}
	_result := pegomock.GetGenericMockFrom(mock).Invoke("SupportsSingleFileDownload", _params, []reflect.Type{reflect.TypeOf((*bool)(nil)).Elem()})
	var _ret0 bool
	if len(_result) != 0 {
		if _result[0] != nil {
			_ret0 = _result[0].(bool)
		}
	}
	return _ret0
}

func (mock *MockClient) UpdateStatus(logger logging.SimpleLogging, repo models.Repo, pull models.PullRequest, state models.CommitStatus, src string, description string, url string) error {
	if mock == nil {
		panic("mock must not be nil. Use myMock := NewMockClient().")
	}
	_params := []pegomock.Param{logger, repo, pull, state, src, description, url}
	_result := pegomock.GetGenericMockFrom(mock).Invoke("UpdateStatus", _params, []reflect.Type{reflect.TypeOf((*error)(nil)).Elem()})
	var _ret0 error
	if len(_result) != 0 {
		if _result[0] != nil {
			_ret0 = _result[0].(error)
		}
	}
	return _ret0
}

func (mock *MockClient) VerifyWasCalledOnce() *VerifierMockClient {
	return &VerifierMockClient{
		mock:                   mock,
		invocationCountMatcher: pegomock.Times(1),
	}
}

func (mock *MockClient) VerifyWasCalled(invocationCountMatcher pegomock.InvocationCountMatcher) *VerifierMockClient {
	return &VerifierMockClient{
		mock:                   mock,
		invocationCountMatcher: invocationCountMatcher,
	}
}

func (mock *MockClient) VerifyWasCalledInOrder(invocationCountMatcher pegomock.InvocationCountMatcher, inOrderContext *pegomock.InOrderContext) *VerifierMockClient {
	return &VerifierMockClient{
		mock:                   mock,
		invocationCountMatcher: invocationCountMatcher,
		inOrderContext:         inOrderContext,
	}
}

func (mock *MockClient) VerifyWasCalledEventually(invocationCountMatcher pegomock.InvocationCountMatcher, timeout time.Duration) *VerifierMockClient {
	return &VerifierMockClient{
		mock:                   mock,
		invocationCountMatcher: invocationCountMatcher,
		timeout:                timeout,
	}
}

type VerifierMockClient struct {
	mock                   *MockClient
	invocationCountMatcher pegomock.InvocationCountMatcher
	inOrderContext         *pegomock.InOrderContext
	timeout                time.Duration
}

func (verifier *VerifierMockClient) CreateComment(logger logging.SimpleLogging, repo models.Repo, pullNum int, comment string, command string) *MockClient_CreateComment_OngoingVerification {
	_params := []pegomock.Param{logger, repo, pullNum, comment, command}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "CreateComment", _params, verifier.timeout)
	return &MockClient_CreateComment_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockClient_CreateComment_OngoingVerification struct {
	mock              *MockClient
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockClient_CreateComment_OngoingVerification) GetCapturedArguments() (logging.SimpleLogging, models.Repo, int, string, string) {
	logger, repo, pullNum, comment, command := c.GetAllCapturedArguments()
	return logger[len(logger)-1], repo[len(repo)-1], pullNum[len(pullNum)-1], comment[len(comment)-1], command[len(command)-1]
}

func (c *MockClient_CreateComment_OngoingVerification) GetAllCapturedArguments() (_param0 []logging.SimpleLogging, _param1 []models.Repo, _param2 []int, _param3 []string, _param4 []string) {
	_params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(_params) > 0 {
		if len(_params) > 0 {
			_param0 = make([]logging.SimpleLogging, len(c.methodInvocations))
			for u, param := range _params[0] {
				_param0[u] = param.(logging.SimpleLogging)
			}
		}
		if len(_params) > 1 {
			_param1 = make([]models.Repo, len(c.methodInvocations))
			for u, param := range _params[1] {
				_param1[u] = param.(models.Repo)
			}
		}
		if len(_params) > 2 {
			_param2 = make([]int, len(c.methodInvocations))
			for u, param := range _params[2] {
				_param2[u] = param.(int)
			}
		}
		if len(_params) > 3 {
			_param3 = make([]string, len(c.methodInvocations))
			for u, param := range _params[3] {
				_param3[u] = param.(string)
			}
		}
		if len(_params) > 4 {
			_param4 = make([]string, len(c.methodInvocations))
			for u, param := range _params[4] {
				_param4[u] = param.(string)
			}
		}
	}
	return
}

func (verifier *VerifierMockClient) DiscardReviews(repo models.Repo, pull models.PullRequest) *MockClient_DiscardReviews_OngoingVerification {
	_params := []pegomock.Param{repo, pull}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "DiscardReviews", _params, verifier.timeout)
	return &MockClient_DiscardReviews_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockClient_DiscardReviews_OngoingVerification struct {
	mock              *MockClient
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockClient_DiscardReviews_OngoingVerification) GetCapturedArguments() (models.Repo, models.PullRequest) {
	repo, pull := c.GetAllCapturedArguments()
	return repo[len(repo)-1], pull[len(pull)-1]
}

func (c *MockClient_DiscardReviews_OngoingVerification) GetAllCapturedArguments() (_param0 []models.Repo, _param1 []models.PullRequest) {
	_params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(_params) > 0 {
		if len(_params) > 0 {
			_param0 = make([]models.Repo, len(c.methodInvocations))
			for u, param := range _params[0] {
				_param0[u] = param.(models.Repo)
			}
		}
		if len(_params) > 1 {
			_param1 = make([]models.PullRequest, len(c.methodInvocations))
			for u, param := range _params[1] {
				_param1[u] = param.(models.PullRequest)
			}
		}
	}
	return
}

func (verifier *VerifierMockClient) GetCloneURL(logger logging.SimpleLogging, VCSHostType models.VCSHostType, repo string) *MockClient_GetCloneURL_OngoingVerification {
	_params := []pegomock.Param{logger, VCSHostType, repo}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "GetCloneURL", _params, verifier.timeout)
	return &MockClient_GetCloneURL_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockClient_GetCloneURL_OngoingVerification struct {
	mock              *MockClient
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockClient_GetCloneURL_OngoingVerification) GetCapturedArguments() (logging.SimpleLogging, models.VCSHostType, string) {
	logger, VCSHostType, repo := c.GetAllCapturedArguments()
	return logger[len(logger)-1], VCSHostType[len(VCSHostType)-1], repo[len(repo)-1]
}

func (c *MockClient_GetCloneURL_OngoingVerification) GetAllCapturedArguments() (_param0 []logging.SimpleLogging, _param1 []models.VCSHostType, _param2 []string) {
	_params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(_params) > 0 {
		if len(_params) > 0 {
			_param0 = make([]logging.SimpleLogging, len(c.methodInvocations))
			for u, param := range _params[0] {
				_param0[u] = param.(logging.SimpleLogging)
			}
		}
		if len(_params) > 1 {
			_param1 = make([]models.VCSHostType, len(c.methodInvocations))
			for u, param := range _params[1] {
				_param1[u] = param.(models.VCSHostType)
			}
		}
		if len(_params) > 2 {
			_param2 = make([]string, len(c.methodInvocations))
			for u, param := range _params[2] {
				_param2[u] = param.(string)
			}
		}
	}
	return
}

func (verifier *VerifierMockClient) GetFileContent(logger logging.SimpleLogging, pull models.PullRequest, fileName string) *MockClient_GetFileContent_OngoingVerification {
	_params := []pegomock.Param{logger, pull, fileName}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "GetFileContent", _params, verifier.timeout)
	return &MockClient_GetFileContent_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockClient_GetFileContent_OngoingVerification struct {
	mock              *MockClient
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockClient_GetFileContent_OngoingVerification) GetCapturedArguments() (logging.SimpleLogging, models.PullRequest, string) {
	logger, pull, fileName := c.GetAllCapturedArguments()
	return logger[len(logger)-1], pull[len(pull)-1], fileName[len(fileName)-1]
}

func (c *MockClient_GetFileContent_OngoingVerification) GetAllCapturedArguments() (_param0 []logging.SimpleLogging, _param1 []models.PullRequest, _param2 []string) {
	_params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(_params) > 0 {
		if len(_params) > 0 {
			_param0 = make([]logging.SimpleLogging, len(c.methodInvocations))
			for u, param := range _params[0] {
				_param0[u] = param.(logging.SimpleLogging)
			}
		}
		if len(_params) > 1 {
			_param1 = make([]models.PullRequest, len(c.methodInvocations))
			for u, param := range _params[1] {
				_param1[u] = param.(models.PullRequest)
			}
		}
		if len(_params) > 2 {
			_param2 = make([]string, len(c.methodInvocations))
			for u, param := range _params[2] {
				_param2[u] = param.(string)
			}
		}
	}
	return
}

func (verifier *VerifierMockClient) GetModifiedFiles(logger logging.SimpleLogging, repo models.Repo, pull models.PullRequest) *MockClient_GetModifiedFiles_OngoingVerification {
	_params := []pegomock.Param{logger, repo, pull}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "GetModifiedFiles", _params, verifier.timeout)
	return &MockClient_GetModifiedFiles_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockClient_GetModifiedFiles_OngoingVerification struct {
	mock              *MockClient
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockClient_GetModifiedFiles_OngoingVerification) GetCapturedArguments() (logging.SimpleLogging, models.Repo, models.PullRequest) {
	logger, repo, pull := c.GetAllCapturedArguments()
	return logger[len(logger)-1], repo[len(repo)-1], pull[len(pull)-1]
}

func (c *MockClient_GetModifiedFiles_OngoingVerification) GetAllCapturedArguments() (_param0 []logging.SimpleLogging, _param1 []models.Repo, _param2 []models.PullRequest) {
	_params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(_params) > 0 {
		if len(_params) > 0 {
			_param0 = make([]logging.SimpleLogging, len(c.methodInvocations))
			for u, param := range _params[0] {
				_param0[u] = param.(logging.SimpleLogging)
			}
		}
		if len(_params) > 1 {
			_param1 = make([]models.Repo, len(c.methodInvocations))
			for u, param := range _params[1] {
				_param1[u] = param.(models.Repo)
			}
		}
		if len(_params) > 2 {
			_param2 = make([]models.PullRequest, len(c.methodInvocations))
			for u, param := range _params[2] {
				_param2[u] = param.(models.PullRequest)
			}
		}
	}
	return
}

func (verifier *VerifierMockClient) GetPullLabels(logger logging.SimpleLogging, repo models.Repo, pull models.PullRequest) *MockClient_GetPullLabels_OngoingVerification {
	_params := []pegomock.Param{logger, repo, pull}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "GetPullLabels", _params, verifier.timeout)
	return &MockClient_GetPullLabels_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockClient_GetPullLabels_OngoingVerification struct {
	mock              *MockClient
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockClient_GetPullLabels_OngoingVerification) GetCapturedArguments() (logging.SimpleLogging, models.Repo, models.PullRequest) {
	logger, repo, pull := c.GetAllCapturedArguments()
	return logger[len(logger)-1], repo[len(repo)-1], pull[len(pull)-1]
}

func (c *MockClient_GetPullLabels_OngoingVerification) GetAllCapturedArguments() (_param0 []logging.SimpleLogging, _param1 []models.Repo, _param2 []models.PullRequest) {
	_params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(_params) > 0 {
		if len(_params) > 0 {
			_param0 = make([]logging.SimpleLogging, len(c.methodInvocations))
			for u, param := range _params[0] {
				_param0[u] = param.(logging.SimpleLogging)
			}
		}
		if len(_params) > 1 {
			_param1 = make([]models.Repo, len(c.methodInvocations))
			for u, param := range _params[1] {
				_param1[u] = param.(models.Repo)
			}
		}
		if len(_params) > 2 {
			_param2 = make([]models.PullRequest, len(c.methodInvocations))
			for u, param := range _params[2] {
				_param2[u] = param.(models.PullRequest)
			}
		}
	}
	return
}

func (verifier *VerifierMockClient) GetTeamNamesForUser(logger logging.SimpleLogging, repo models.Repo, user models.User) *MockClient_GetTeamNamesForUser_OngoingVerification {
	_params := []pegomock.Param{logger, repo, user}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "GetTeamNamesForUser", _params, verifier.timeout)
	return &MockClient_GetTeamNamesForUser_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockClient_GetTeamNamesForUser_OngoingVerification struct {
	mock              *MockClient
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockClient_GetTeamNamesForUser_OngoingVerification) GetCapturedArguments() (logging.SimpleLogging, models.Repo, models.User) {
	logger, repo, user := c.GetAllCapturedArguments()
	return logger[len(logger)-1], repo[len(repo)-1], user[len(user)-1]
}

func (c *MockClient_GetTeamNamesForUser_OngoingVerification) GetAllCapturedArguments() (_param0 []logging.SimpleLogging, _param1 []models.Repo, _param2 []models.User) {
	_params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(_params) > 0 {
		if len(_params) > 0 {
			_param0 = make([]logging.SimpleLogging, len(c.methodInvocations))
			for u, param := range _params[0] {
				_param0[u] = param.(logging.SimpleLogging)
			}
		}
		if len(_params) > 1 {
			_param1 = make([]models.Repo, len(c.methodInvocations))
			for u, param := range _params[1] {
				_param1[u] = param.(models.Repo)
			}
		}
		if len(_params) > 2 {
			_param2 = make([]models.User, len(c.methodInvocations))
			for u, param := range _params[2] {
				_param2[u] = param.(models.User)
			}
		}
	}
	return
}

func (verifier *VerifierMockClient) HidePrevCommandComments(logger logging.SimpleLogging, repo models.Repo, pullNum int, command string, dir string) *MockClient_HidePrevCommandComments_OngoingVerification {
	_params := []pegomock.Param{logger, repo, pullNum, command, dir}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "HidePrevCommandComments", _params, verifier.timeout)
	return &MockClient_HidePrevCommandComments_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockClient_HidePrevCommandComments_OngoingVerification struct {
	mock              *MockClient
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockClient_HidePrevCommandComments_OngoingVerification) GetCapturedArguments() (logging.SimpleLogging, models.Repo, int, string, string) {
	logger, repo, pullNum, command, dir := c.GetAllCapturedArguments()
	return logger[len(logger)-1], repo[len(repo)-1], pullNum[len(pullNum)-1], command[len(command)-1], dir[len(dir)-1]
}

func (c *MockClient_HidePrevCommandComments_OngoingVerification) GetAllCapturedArguments() (_param0 []logging.SimpleLogging, _param1 []models.Repo, _param2 []int, _param3 []string, _param4 []string) {
	_params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(_params) > 0 {
		if len(_params) > 0 {
			_param0 = make([]logging.SimpleLogging, len(c.methodInvocations))
			for u, param := range _params[0] {
				_param0[u] = param.(logging.SimpleLogging)
			}
		}
		if len(_params) > 1 {
			_param1 = make([]models.Repo, len(c.methodInvocations))
			for u, param := range _params[1] {
				_param1[u] = param.(models.Repo)
			}
		}
		if len(_params) > 2 {
			_param2 = make([]int, len(c.methodInvocations))
			for u, param := range _params[2] {
				_param2[u] = param.(int)
			}
		}
		if len(_params) > 3 {
			_param3 = make([]string, len(c.methodInvocations))
			for u, param := range _params[3] {
				_param3[u] = param.(string)
			}
		}
		if len(_params) > 4 {
			_param4 = make([]string, len(c.methodInvocations))
			for u, param := range _params[4] {
				_param4[u] = param.(string)
			}
		}
	}
	return
}

func (verifier *VerifierMockClient) MarkdownPullLink(pull models.PullRequest) *MockClient_MarkdownPullLink_OngoingVerification {
	_params := []pegomock.Param{pull}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "MarkdownPullLink", _params, verifier.timeout)
	return &MockClient_MarkdownPullLink_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockClient_MarkdownPullLink_OngoingVerification struct {
	mock              *MockClient
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockClient_MarkdownPullLink_OngoingVerification) GetCapturedArguments() models.PullRequest {
	pull := c.GetAllCapturedArguments()
	return pull[len(pull)-1]
}

func (c *MockClient_MarkdownPullLink_OngoingVerification) GetAllCapturedArguments() (_param0 []models.PullRequest) {
	_params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(_params) > 0 {
		if len(_params) > 0 {
			_param0 = make([]models.PullRequest, len(c.methodInvocations))
			for u, param := range _params[0] {
				_param0[u] = param.(models.PullRequest)
			}
		}
	}
	return
}

func (verifier *VerifierMockClient) MergePull(logger logging.SimpleLogging, pull models.PullRequest, pullOptions models.PullRequestOptions) *MockClient_MergePull_OngoingVerification {
	_params := []pegomock.Param{logger, pull, pullOptions}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "MergePull", _params, verifier.timeout)
	return &MockClient_MergePull_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockClient_MergePull_OngoingVerification struct {
	mock              *MockClient
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockClient_MergePull_OngoingVerification) GetCapturedArguments() (logging.SimpleLogging, models.PullRequest, models.PullRequestOptions) {
	logger, pull, pullOptions := c.GetAllCapturedArguments()
	return logger[len(logger)-1], pull[len(pull)-1], pullOptions[len(pullOptions)-1]
}

func (c *MockClient_MergePull_OngoingVerification) GetAllCapturedArguments() (_param0 []logging.SimpleLogging, _param1 []models.PullRequest, _param2 []models.PullRequestOptions) {
	_params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(_params) > 0 {
		if len(_params) > 0 {
			_param0 = make([]logging.SimpleLogging, len(c.methodInvocations))
			for u, param := range _params[0] {
				_param0[u] = param.(logging.SimpleLogging)
			}
		}
		if len(_params) > 1 {
			_param1 = make([]models.PullRequest, len(c.methodInvocations))
			for u, param := range _params[1] {
				_param1[u] = param.(models.PullRequest)
			}
		}
		if len(_params) > 2 {
			_param2 = make([]models.PullRequestOptions, len(c.methodInvocations))
			for u, param := range _params[2] {
				_param2[u] = param.(models.PullRequestOptions)
			}
		}
	}
	return
}

func (verifier *VerifierMockClient) PullIsApproved(logger logging.SimpleLogging, repo models.Repo, pull models.PullRequest) *MockClient_PullIsApproved_OngoingVerification {
	_params := []pegomock.Param{logger, repo, pull}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "PullIsApproved", _params, verifier.timeout)
	return &MockClient_PullIsApproved_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockClient_PullIsApproved_OngoingVerification struct {
	mock              *MockClient
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockClient_PullIsApproved_OngoingVerification) GetCapturedArguments() (logging.SimpleLogging, models.Repo, models.PullRequest) {
	logger, repo, pull := c.GetAllCapturedArguments()
	return logger[len(logger)-1], repo[len(repo)-1], pull[len(pull)-1]
}

func (c *MockClient_PullIsApproved_OngoingVerification) GetAllCapturedArguments() (_param0 []logging.SimpleLogging, _param1 []models.Repo, _param2 []models.PullRequest) {
	_params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(_params) > 0 {
		if len(_params) > 0 {
			_param0 = make([]logging.SimpleLogging, len(c.methodInvocations))
			for u, param := range _params[0] {
				_param0[u] = param.(logging.SimpleLogging)
			}
		}
		if len(_params) > 1 {
			_param1 = make([]models.Repo, len(c.methodInvocations))
			for u, param := range _params[1] {
				_param1[u] = param.(models.Repo)
			}
		}
		if len(_params) > 2 {
			_param2 = make([]models.PullRequest, len(c.methodInvocations))
			for u, param := range _params[2] {
				_param2[u] = param.(models.PullRequest)
			}
		}
	}
	return
}

func (verifier *VerifierMockClient) PullIsMergeable(logger logging.SimpleLogging, repo models.Repo, pull models.PullRequest, vcsstatusname string) *MockClient_PullIsMergeable_OngoingVerification {
	_params := []pegomock.Param{logger, repo, pull, vcsstatusname}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "PullIsMergeable", _params, verifier.timeout)
	return &MockClient_PullIsMergeable_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockClient_PullIsMergeable_OngoingVerification struct {
	mock              *MockClient
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockClient_PullIsMergeable_OngoingVerification) GetCapturedArguments() (logging.SimpleLogging, models.Repo, models.PullRequest, string) {
	logger, repo, pull, vcsstatusname := c.GetAllCapturedArguments()
	return logger[len(logger)-1], repo[len(repo)-1], pull[len(pull)-1], vcsstatusname[len(vcsstatusname)-1]
}

func (c *MockClient_PullIsMergeable_OngoingVerification) GetAllCapturedArguments() (_param0 []logging.SimpleLogging, _param1 []models.Repo, _param2 []models.PullRequest, _param3 []string) {
	_params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(_params) > 0 {
		if len(_params) > 0 {
			_param0 = make([]logging.SimpleLogging, len(c.methodInvocations))
			for u, param := range _params[0] {
				_param0[u] = param.(logging.SimpleLogging)
			}
		}
		if len(_params) > 1 {
			_param1 = make([]models.Repo, len(c.methodInvocations))
			for u, param := range _params[1] {
				_param1[u] = param.(models.Repo)
			}
		}
		if len(_params) > 2 {
			_param2 = make([]models.PullRequest, len(c.methodInvocations))
			for u, param := range _params[2] {
				_param2[u] = param.(models.PullRequest)
			}
		}
		if len(_params) > 3 {
			_param3 = make([]string, len(c.methodInvocations))
			for u, param := range _params[3] {
				_param3[u] = param.(string)
			}
		}
	}
	return
}

func (verifier *VerifierMockClient) ReactToComment(logger logging.SimpleLogging, repo models.Repo, pullNum int, commentID int64, reaction string) *MockClient_ReactToComment_OngoingVerification {
	_params := []pegomock.Param{logger, repo, pullNum, commentID, reaction}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "ReactToComment", _params, verifier.timeout)
	return &MockClient_ReactToComment_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockClient_ReactToComment_OngoingVerification struct {
	mock              *MockClient
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockClient_ReactToComment_OngoingVerification) GetCapturedArguments() (logging.SimpleLogging, models.Repo, int, int64, string) {
	logger, repo, pullNum, commentID, reaction := c.GetAllCapturedArguments()
	return logger[len(logger)-1], repo[len(repo)-1], pullNum[len(pullNum)-1], commentID[len(commentID)-1], reaction[len(reaction)-1]
}

func (c *MockClient_ReactToComment_OngoingVerification) GetAllCapturedArguments() (_param0 []logging.SimpleLogging, _param1 []models.Repo, _param2 []int, _param3 []int64, _param4 []string) {
	_params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(_params) > 0 {
		if len(_params) > 0 {
			_param0 = make([]logging.SimpleLogging, len(c.methodInvocations))
			for u, param := range _params[0] {
				_param0[u] = param.(logging.SimpleLogging)
			}
		}
		if len(_params) > 1 {
			_param1 = make([]models.Repo, len(c.methodInvocations))
			for u, param := range _params[1] {
				_param1[u] = param.(models.Repo)
			}
		}
		if len(_params) > 2 {
			_param2 = make([]int, len(c.methodInvocations))
			for u, param := range _params[2] {
				_param2[u] = param.(int)
			}
		}
		if len(_params) > 3 {
			_param3 = make([]int64, len(c.methodInvocations))
			for u, param := range _params[3] {
				_param3[u] = param.(int64)
			}
		}
		if len(_params) > 4 {
			_param4 = make([]string, len(c.methodInvocations))
			for u, param := range _params[4] {
				_param4[u] = param.(string)
			}
		}
	}
	return
}

func (verifier *VerifierMockClient) SupportsSingleFileDownload(repo models.Repo) *MockClient_SupportsSingleFileDownload_OngoingVerification {
	_params := []pegomock.Param{repo}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "SupportsSingleFileDownload", _params, verifier.timeout)
	return &MockClient_SupportsSingleFileDownload_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockClient_SupportsSingleFileDownload_OngoingVerification struct {
	mock              *MockClient
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockClient_SupportsSingleFileDownload_OngoingVerification) GetCapturedArguments() models.Repo {
	repo := c.GetAllCapturedArguments()
	return repo[len(repo)-1]
}

func (c *MockClient_SupportsSingleFileDownload_OngoingVerification) GetAllCapturedArguments() (_param0 []models.Repo) {
	_params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(_params) > 0 {
		if len(_params) > 0 {
			_param0 = make([]models.Repo, len(c.methodInvocations))
			for u, param := range _params[0] {
				_param0[u] = param.(models.Repo)
			}
		}
	}
	return
}

func (verifier *VerifierMockClient) UpdateStatus(logger logging.SimpleLogging, repo models.Repo, pull models.PullRequest, state models.CommitStatus, src string, description string, url string) *MockClient_UpdateStatus_OngoingVerification {
	_params := []pegomock.Param{logger, repo, pull, state, src, description, url}
	methodInvocations := pegomock.GetGenericMockFrom(verifier.mock).Verify(verifier.inOrderContext, verifier.invocationCountMatcher, "UpdateStatus", _params, verifier.timeout)
	return &MockClient_UpdateStatus_OngoingVerification{mock: verifier.mock, methodInvocations: methodInvocations}
}

type MockClient_UpdateStatus_OngoingVerification struct {
	mock              *MockClient
	methodInvocations []pegomock.MethodInvocation
}

func (c *MockClient_UpdateStatus_OngoingVerification) GetCapturedArguments() (logging.SimpleLogging, models.Repo, models.PullRequest, models.CommitStatus, string, string, string) {
	logger, repo, pull, state, src, description, url := c.GetAllCapturedArguments()
	return logger[len(logger)-1], repo[len(repo)-1], pull[len(pull)-1], state[len(state)-1], src[len(src)-1], description[len(description)-1], url[len(url)-1]
}

func (c *MockClient_UpdateStatus_OngoingVerification) GetAllCapturedArguments() (_param0 []logging.SimpleLogging, _param1 []models.Repo, _param2 []models.PullRequest, _param3 []models.CommitStatus, _param4 []string, _param5 []string, _param6 []string) {
	_params := pegomock.GetGenericMockFrom(c.mock).GetInvocationParams(c.methodInvocations)
	if len(_params) > 0 {
		if len(_params) > 0 {
			_param0 = make([]logging.SimpleLogging, len(c.methodInvocations))
			for u, param := range _params[0] {
				_param0[u] = param.(logging.SimpleLogging)
			}
		}
		if len(_params) > 1 {
			_param1 = make([]models.Repo, len(c.methodInvocations))
			for u, param := range _params[1] {
				_param1[u] = param.(models.Repo)
			}
		}
		if len(_params) > 2 {
			_param2 = make([]models.PullRequest, len(c.methodInvocations))
			for u, param := range _params[2] {
				_param2[u] = param.(models.PullRequest)
			}
		}
		if len(_params) > 3 {
			_param3 = make([]models.CommitStatus, len(c.methodInvocations))
			for u, param := range _params[3] {
				_param3[u] = param.(models.CommitStatus)
			}
		}
		if len(_params) > 4 {
			_param4 = make([]string, len(c.methodInvocations))
			for u, param := range _params[4] {
				_param4[u] = param.(string)
			}
		}
		if len(_params) > 5 {
			_param5 = make([]string, len(c.methodInvocations))
			for u, param := range _params[5] {
				_param5[u] = param.(string)
			}
		}
		if len(_params) > 6 {
			_param6 = make([]string, len(c.methodInvocations))
			for u, param := range _params[6] {
				_param6[u] = param.(string)
			}
		}
	}
	return
}
