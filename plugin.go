package main

import (
	"log"

	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/ryotarai/docker-authz-mruby/evaluator"
)

type Plugin struct {
	RuleScript string
}

func NewPlugin(rule string) *Plugin {
	return &Plugin{
		RuleScript: rule,
	}
}

func (p *Plugin) AuthZReq(req authorization.Request) authorization.Response {
	e := evaluator.NewEvaluator(p.RuleScript, req)
	allow, msg, err := e.Evaluate()
	if err != nil {
		log.Printf("ERROR: %s", err)
		return authorization.Response{
			Allow: false,
			Err:   "authorization script failed",
		}
	}

	return authorization.Response{
		Allow: allow,
		Err:   msg,
	}
}

func (p *Plugin) AuthZRes(req authorization.Request) authorization.Response {
	return authorization.Response{
		Allow: true,
	}
}
