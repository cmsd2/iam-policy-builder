package builder

import (
	"errors"
	"regexp"
	"strings"
)

const (
	Get     = "GET"
	Post    = "POST"
	Put     = "PUT"
	Patch   = "PATCH"
	Head    = "HEAD"
	Delete  = "DELETE"
	Options = "OPTIONS"
	All     = "*"

	Allow = "Allow"
	Deny  = "Deny"
)

var ErrInvalidHttpVerb = errors.New("invalid http verb")
var ErrInvalidResource = errors.New("invalid resource")
var ErrInvalidEffect = errors.New("invalid effect")
var ErrNoStatements = errors.New("no statements")

var verbs = []string{Get, Post, Put, Patch, Head, Delete, Options}

type AuthPolicy struct {
	AwsAccountId string
	PrincipalId  string
	Version      string
	PathRegex    *regexp.Regexp

	AllowMethods []*Method
	DenyMethods  []*Method

	RestApiId string
	Region    string
	Stage     string
}

type Method struct {
	ResourceArn string
	Conditions  interface{}
}

type Statement struct {
	Action    string
	Effect    string
	Resource  []string
	Condition interface{}
}

type PolicyDocument struct {
	Version   string
	Statement []*Statement
}

type Policy struct {
	PolicyDocument PolicyDocument
	PrincipalId    string
}

func NewAuthPolicy(principalId string, awsAccountId string) *AuthPolicy {
	return &AuthPolicy{
		AwsAccountId: awsAccountId,
		PrincipalId:  principalId,
		Version:      "2012-10-17",
		PathRegex:    regexp.MustCompile("^[/.a-zA-Z0-9-\\*]+$"),

		AllowMethods: make([]*Method, 0),
		DenyMethods:  make([]*Method, 0),

		RestApiId: "*",
		Region:    "*",
		Stage:     "*",
	}
}

func NewMethod(resourceArn string, conditions interface{}) *Method {
	return &Method{
		ResourceArn: resourceArn,
		Conditions:  conditions,
	}
}

func NewEmptyStatement(effect string) (*Statement, error) {
	effect, err := NormaliseEffect(effect)
	if err != nil {
		return nil, err
	}

	return &Statement{
		Action:    "execute-api:Invoke",
		Resource:  make([]string, 0),
		Effect:    effect,
		Condition: make(map[string]string),
	}, nil
}

func StatementsForEffect(effect string, methods []*Method) ([]*Statement, error) {
	statements := make([]*Statement, 0)

	if len(methods) != 0 {
		statement, err := NewEmptyStatement(effect)
		if err != nil {
			return nil, err
		}

		for _, method := range methods {
			if method.Conditions == nil {
				statement.Resource = append(statement.Resource, method.ResourceArn)
			} else {
				conditionalStatement, err := NewEmptyStatement(effect)
				if err != nil {
					return nil, err
				}

				conditionalStatement.Resource = append(conditionalStatement.Resource, method.ResourceArn)
				conditionalStatement.Condition = method.Conditions
				statements = append(statements, conditionalStatement)
			}
		}

		statements = append(statements, statement)
	}

	return statements, nil
}

func NormaliseEffect(effect string) (string, error) {
	effect = strings.ToUpper(effect[:1]) + strings.ToLower(effect[1:])
	if effect != Allow && effect != Deny {
		return effect, ErrInvalidEffect
	}
	return effect, nil
}

func (p *AuthPolicy) AllowAllMethods() {
	p.addMethod(Allow, All, All, nil)
}

func (p *AuthPolicy) DenyAllMethods() {
	p.addMethod(Deny, All, All, nil)
}

func (p *AuthPolicy) AllowMethod(verb string, resource string) {
	p.addMethod(Allow, verb, resource, nil)
}

func (p *AuthPolicy) DenyMethod(verb string, resource string) {
	p.addMethod(Deny, verb, resource, nil)
}

func (p *AuthPolicy) AllowMethodWithConditions(verb string, resource string, conditions interface{}) {
	p.addMethod(Allow, verb, resource, conditions)
}

func (p *AuthPolicy) DenyMethodWithConditions(verb string, resource string, conditions interface{}) {
	p.addMethod(Deny, verb, resource, conditions)
}

func (p *AuthPolicy) addMethod(effect string /* ALLOW|DENY */, verb string /* Http Verb */, resource string, conditions interface{}) error {
	if verb != All && !containsString(verbs, verb) {
		return ErrInvalidHttpVerb
	}

	if !p.PathRegex.MatchString(resource) {
		return ErrInvalidResource
	}

	if resource[:1] == "/" {
		resource = resource[1:]
	}

	resourceArn := ("arn:aws:execute-api:" +
		p.Region + ":" +
		p.AwsAccountId + ":" +
		p.RestApiId + "/" +
		p.Stage + "/" +
		verb + "/" +
		resource)

	effect, err := NormaliseEffect(effect)
	if err != nil {
		return ErrInvalidEffect
	}

	if effect == Allow {
		p.AllowMethods = append(p.AllowMethods, NewMethod(resourceArn, conditions))
	} else if effect == Deny {
		p.DenyMethods = append(p.DenyMethods, NewMethod(resourceArn, conditions))
	} else {
		return ErrInvalidEffect
	}

	return nil
}

func (p *AuthPolicy) Build() (*Policy, error) {
	if len(p.AllowMethods) == 0 && len(p.DenyMethods) == 0 {
		return nil, ErrNoStatements
	}

	var statements []*Statement

	allows, err := StatementsForEffect(Allow, p.AllowMethods)
	if err != nil {
		return nil, err
	}

	denies, err := StatementsForEffect(Deny, p.DenyMethods)
	if err != nil {
		return nil, err
	}

	statements = append(statements, allows...)
	statements = append(statements, denies...)

	return NewPolicy(p.PrincipalId, p.Version, statements)
}

func NewPolicy(principalId string, version string, statements []*Statement) (*Policy, error) {
	if len(statements) == 0 {
		return nil, ErrNoStatements
	}

	return &Policy{
		PrincipalId: principalId,
		PolicyDocument: PolicyDocument{
			Version:   version,
			Statement: statements,
		},
	}, nil
}

func containsString(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
