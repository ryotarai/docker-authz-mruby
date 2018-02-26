package evaluator

import (
	"testing"

	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/stretchr/testify/assert"
)

func TestEvaluatorAllow(t *testing.T) {
	script := `
	  allow
	`
	req := authorization.Request{}
	e := NewEvaluator(script, req)
	allow, message, err := e.Evaluate()
	assert.NoError(t, err)
	assert.Equal(t, "", message)
	assert.True(t, allow)
}

func TestEvaluatorDeny(t *testing.T) {
	script := `
	  deny("MESSAGE")
	`
	req := authorization.Request{}
	e := NewEvaluator(script, req)
	allow, message, err := e.Evaluate()
	assert.NoError(t, err)
	assert.Equal(t, "MESSAGE", message)
	assert.False(t, allow)
}

func TestEvaluatorImplicitlyDeny(t *testing.T) {
	script := ""
	req := authorization.Request{}
	e := NewEvaluator(script, req)
	allow, message, err := e.Evaluate()
	assert.NoError(t, err)
	assert.Equal(t, "implicitly denied", message)
	assert.False(t, allow)
}

func TestEvaluatorException(t *testing.T) {
	script := "raise 'ERROR'"
	req := authorization.Request{}
	e := NewEvaluator(script, req)
	allow, message, err := e.Evaluate()
	assert.Error(t, err)
	assert.Equal(t, "error in mruby script", message)
	assert.False(t, allow)
}

func TestEvaluatorValues(t *testing.T) {
	req := authorization.Request{
		User:            "USER",
		UserAuthNMethod: "AUTHN",
		RequestMethod:   "GET",
		RequestURI:      "/foo?bar=baz",
		RequestBody:     []byte("{\"foo\": \"bar\"}\n"),
		RequestHeaders:  map[string]string{"foo": "bar"},
	}
	script := `
	  raise unless user == "USER"
	  raise unless user_authn_method == "AUTHN"
	  raise unless request_method == "GET"
	  raise unless request_uri == "/foo?bar=baz"
	  raise unless request_uri_path == "/foo"
	  raise unless request_uri_query == {"bar" => ["baz"]}
	  raise unless request_body == {"foo" => "bar"}
	  raise unless request_headers == {"foo" => "bar"}
	`
	e := NewEvaluator(script, req)
	_, _, err := e.Evaluate()
	assert.NoError(t, err)
}
