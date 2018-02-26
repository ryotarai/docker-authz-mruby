package evaluator

import (
	"fmt"
	"log"
	"net/url"

	"github.com/docker/go-plugins-helpers/authorization"
	mruby "github.com/mitchellh/go-mruby"
)

type EvaluatorIF interface {
	Evaluate(req authorization.Request) (bool, string, string, error)
}

type Evaluator struct {
	Script  string
	Request authorization.Request
	status  string
	message string
}

func NewEvaluator(s string, req authorization.Request) *Evaluator {
	return &Evaluator{
		Script:  s,
		Request: req,
	}
}

func (e *Evaluator) Evaluate() (bool, string, error) {
	var err error

	mrb := mruby.NewMrb()
	defer mrb.Close()

	e.prepare(mrb)
	_, err = mrb.LoadString(e.Script)
	if err != nil {
		log.Printf("ERROR: during evaluating mruby script: %v", err)
		return false, "error in mruby script", err
	}

	if e.status == "allowed" {
		return true, e.message, nil
	}
	if e.status == "denied" {
		return false, e.message, nil
	}
	return false, "implicitly denied", nil
}

func (e *Evaluator) prepare(mrb *mruby.Mrb) {
	kernel := mrb.Module("Kernel")
	kernel.DefineMethod("allow", e.allowFunc, mruby.ArgsNone())
	kernel.DefineMethod("deny", e.denyFunc, mruby.ArgsArg(0, 1))
	kernel.DefineMethod("request_method", e.requestMethodFunc, mruby.ArgsNone())
	kernel.DefineMethod("request_uri", e.requestURIFunc, mruby.ArgsNone())
	kernel.DefineMethod("request_uri_path", e.requestURIPathFunc, mruby.ArgsNone())
	kernel.DefineMethod("request_uri_query", e.requestURIQueryFunc, mruby.ArgsNone())
	kernel.DefineMethod("request_headers", e.requestHeadersFunc, mruby.ArgsNone())
	kernel.DefineMethod("request_body_json", e.requestBodyJSONFunc, mruby.ArgsNone())
	kernel.DefineMethod("user", e.userFunc, mruby.ArgsNone())
	kernel.DefineMethod("user_authn_method", e.userAuthNMethodFunc, mruby.ArgsNone())

	_, err := mrb.LoadString(`
		def request_body
		  return nil if request_body_json.empty?
		  @request_body ||= JSON.parse(request_body_json)
		end
	`)
	if err != nil {
		panic(err)
	}
}

func stringToSymbol(m *mruby.Mrb, s string) *mruby.MrbValue {
	sym, err := mruby.String(s).MrbValue(m).Call("to_sym")
	if err != nil {
		panic(err)
	}
	return sym
}

func resultHashToString(m *mruby.Mrb, hash *mruby.MrbValue) (string, string) {
	var msg, e string
	v, err := hash.Hash().Get(stringToSymbol(m, "message"))
	if err == nil {
		msg = v.String()
	}
	v, err = hash.Hash().Get(stringToSymbol(m, "error"))
	if err == nil {
		msg = v.String()
	}
	return msg, e
}

func (e *Evaluator) allowFunc(m *mruby.Mrb, self *mruby.MrbValue) (mruby.Value, mruby.Value) {
	if e.status != "" {
		return nil, stringToException(m, fmt.Sprintf("already %s", e.status))
	}
	e.status = "allowed"
	return nil, nil
}

func (e *Evaluator) denyFunc(m *mruby.Mrb, self *mruby.MrbValue) (mruby.Value, mruby.Value) {
	if e.status != "" {
		return nil, stringToException(m, fmt.Sprintf("already %s", e.status))
	}
	args := m.GetArgs()
	if len(args) == 1 {
		e.message = args[0].String()
	}
	e.status = "denied"
	return nil, nil
}

func (e *Evaluator) requestMethodFunc(m *mruby.Mrb, self *mruby.MrbValue) (mruby.Value, mruby.Value) {
	return mruby.String(e.Request.RequestMethod).MrbValue(m), nil
}

func (e *Evaluator) requestURIFunc(m *mruby.Mrb, self *mruby.MrbValue) (mruby.Value, mruby.Value) {
	return mruby.String(e.Request.RequestURI).MrbValue(m), nil
}

func (e *Evaluator) requestURIQueryFunc(m *mruby.Mrb, self *mruby.MrbValue) (mruby.Value, mruby.Value) {
	uri, err := url.Parse(e.Request.RequestURI)
	if err != nil {
		return nil, stringToException(m, err.Error())
	}
	return stringMapListToHash(m, uri.Query()), nil
}

func (e *Evaluator) requestURIPathFunc(m *mruby.Mrb, self *mruby.MrbValue) (mruby.Value, mruby.Value) {
	uri, err := url.Parse(e.Request.RequestURI)
	if err != nil {
		return nil, stringToException(m, err.Error())
	}
	return mruby.String(uri.Path).MrbValue(m), nil
}

func stringToException(m *mruby.Mrb, s string) mruby.Value {
	e, err := m.Class("StandardError", nil).New(mruby.String(s))
	if err != nil {
		panic(err)
	}
	return e
}

func stringMapToHash(m *mruby.Mrb, mp map[string]string) mruby.Value {
	hash, err := m.Class("Hash", nil).New()
	if err != nil {
		panic(err)
	}
	h := hash.Hash()

	for k, v := range mp {
		h.Set(mruby.String(k).MrbValue(m), mruby.String(v).MrbValue(m))
	}
	return hash
}

func stringMapListToHash(m *mruby.Mrb, mp map[string][]string) mruby.Value {
	hash, err := m.Class("Hash", nil).New()
	if err != nil {
		panic(err)
	}
	h := hash.Hash()

	for k, v := range mp {
		ary, err := m.Class("Array", nil).New()
		if err != nil {
			panic(err)
		}
		for _, e := range v {
			ary.Call("push", mruby.String(e).MrbValue(m))
		}
		h.Set(mruby.String(k).MrbValue(m), ary)
	}
	return hash
}

func (e *Evaluator) requestHeadersFunc(m *mruby.Mrb, self *mruby.MrbValue) (mruby.Value, mruby.Value) {
	return stringMapToHash(m, e.Request.RequestHeaders), nil
}

func (e *Evaluator) userFunc(m *mruby.Mrb, self *mruby.MrbValue) (mruby.Value, mruby.Value) {
	return mruby.String(e.Request.User).MrbValue(m), nil
}

func (e *Evaluator) userAuthNMethodFunc(m *mruby.Mrb, self *mruby.MrbValue) (mruby.Value, mruby.Value) {
	return mruby.String(e.Request.UserAuthNMethod).MrbValue(m), nil
}

func (e *Evaluator) requestBodyJSONFunc(m *mruby.Mrb, self *mruby.MrbValue) (mruby.Value, mruby.Value) {
	return mruby.String(string(e.Request.RequestBody)).MrbValue(m), nil
}
