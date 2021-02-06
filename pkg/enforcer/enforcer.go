// Copyright 2021 The Cockroach Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package enforcer

import (
	"context"
	"fmt"

	"strings"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/api/capabilities"
	"github.com/bobvawter/cacheroach/api/principal"
	"github.com/bobvawter/cacheroach/api/session"
	"github.com/bobvawter/cacheroach/api/tenant"
	"github.com/bobvawter/cacheroach/api/token"
	"github.com/bobvawter/cacheroach/api/vhost"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/google/wire"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

const idFieldName = "ID"

// Set is used by wire.
var Set = wire.NewSet(ProvideEnforcer)

// Used to memoize the id field within a given message type.
type idMap map[protoreflect.MessageType]protoreflect.FieldDescriptor

// extract returns the value of the ID field in the target message or
// returns nil.
func (m idMap) extract(msg proto.Message) proto.Message {
	if msg.ProtoReflect().Descriptor().Name() == idFieldName {
		return msg
	}
	ref := msg.ProtoReflect()
	if fd := m[ref.Type()]; fd != nil && ref.Has(fd) {
		return ref.Get(fd).Message().Interface()
	}
	return nil
}

type ruleMap map[protoreflect.Descriptor]*capabilities.Rule

// Enforcer applies a rule-set to protobuf messages.
type Enforcer struct {
	idMap   idMap
	logger  *log.Logger
	tokens  token.TokensServer
	ruleMap ruleMap
}

// ProvideEnforcer is used by wire.
func ProvideEnforcer(logger *log.Logger, tokens token.TokensServer) *Enforcer {
	e := &Enforcer{
		idMap:   make(idMap),
		logger:  logger,
		tokens:  tokens,
		ruleMap: make(ruleMap),
	}
	protoregistry.GlobalTypes.RangeMessages(func(typ protoreflect.MessageType) bool {
		fields := typ.Descriptor().Fields()

		idField := fields.ByName(idFieldName)
		if idField == nil {
			idField = fields.ByName(protoreflect.Name(strings.ToLower(idFieldName)))
		}
		if idField != nil {
			if msg := idField.Message(); msg != nil {
				e.idMap[typ] = idField
				logger.Tracef("ID field %s", idField.FullName())
			}
		}

		if opts := typ.Descriptor().Options(); proto.HasExtension(opts, capabilities.E_MsgRule) {
			r := proto.GetExtension(opts, capabilities.E_MsgRule).(*capabilities.Rule)
			e.ruleMap[typ.Descriptor()] = r
			logger.Tracef("Message rule %s -> %s", typ.Descriptor().FullName(), r)
		}

		for i, j := 0, fields.Len(); i < j; i++ {
			fd := fields.Get(i)
			if opts := fd.Options(); proto.HasExtension(opts, capabilities.E_FieldRule) {
				r := proto.GetExtension(opts, capabilities.E_FieldRule).(*capabilities.Rule)
				e.ruleMap[fd] = r
				logger.Tracef("Field rule %s -> %s", fd.FullName(), r)
			}
		}

		return true
	})
	return e
}

// Check returns true if the rule can be satisfied solely by the context.
func (e *Enforcer) Check(ctx context.Context, rule *capabilities.Rule) (bool, error) {
	ev := eval{
		Context:  ctx,
		Enforcer: e,
		sn:       session.FromContext(ctx)}
	if ev.sn == nil {
		ev.sn = &session.Session{}
	}
	return ev.Eval(rule)
}

// Enforce modifies the given message in-place in order to conform to
// the embedded rule-set. The method returns true if the message already
// complied with the rule-set (i.e. no modifications were made).
func (e *Enforcer) Enforce(
	ctx context.Context, dir capabilities.Direction, val protoreflect.Value,
) (bool, error) {
	ev := eval{
		Context:   ctx,
		Enforcer:  e,
		direction: dir,
		seen:      make(map[proto.Message]bool, 16),
		sn:        session.FromContext(ctx),
	}
	if ev.sn == nil {
		ev.sn = &session.Session{}
	}
	return ev.Walk(val)
}

type eval struct {
	context.Context
	*Enforcer
	direction capabilities.Direction
	// The current message stack.
	messages []proto.Message
	// A stack of objects which provides ID information.
	ids []proto.Message
	// Break cycles if working from degenerate object graph.
	seen  map[proto.Message]bool
	sn    *session.Session
	rules []*capabilities.Rule
}

// Resolve maps the rule reference to an actual value.
func (e *eval) Resolve(r *capabilities.Reference) (proto.Message, error) {
	if r == nil {
		return nil, nil
	}

	switch t := r.Kind.(type) {
	case *capabilities.Reference_Context:
		switch t.Context {
		case capabilities.ContextReference_INVALID_CONTEXT:
			return nil, errors.New("invalid context")
		case capabilities.ContextReference_SESSION_PRINCIPAL:
			return session.FromContext(e).GetPrincipalId(), nil
		case capabilities.ContextReference_SCOPE_TENANT:
			return session.FromContext(e).GetScope().GetOnLocation().GetTenantId(), nil
		case capabilities.ContextReference_SCOPE_PRINCIPAL:
			return session.FromContext(e).GetScope().GetOnPrincipal(), nil
		case capabilities.ContextReference_UNAUTHENTICATED_PRINCIPAL:
			return principal.Unauthenticated, nil
		case capabilities.ContextReference_VHOST_TENANT:
			return vhost.FromContext(e).GetTenantId(), nil
		default:
			return nil, errors.Errorf("unimplemented: %d", t.Context)
		}

	case *capabilities.Reference_Field:
		if len(e.messages) == 0 {
			return nil, errors.New("empty stack")
		}
		top := e.messages[len(e.messages)-1]
		ref := top.ProtoReflect()
		fields := ref.Descriptor().Fields()

		fd := fields.ByNumber(protoreflect.FieldNumber(t.Field))
		if fd == nil {
			return nil, errors.Errorf("no field numbered %d in %s", t.Field, ref.Descriptor().FullName())
		}

		if !ref.Has(fd) {
			return nil, nil
		}

		switch fd.Kind() {
		case protoreflect.MessageKind:
			return ref.Get(fd).Message().Interface(), nil
		case protoreflect.StringKind:
			return &wrappers.StringValue{Value: ref.Get(fd).String()}, nil
		default:
			return nil, errors.Errorf("unimplemented field kind %d", fd.Kind())
		}

	case *capabilities.Reference_StringValue:
		return &wrappers.StringValue{Value: t.StringValue}, nil

	default:
		return nil, errors.Errorf("unimplemented: %T", t)
	}
}

// Dereference returns the (possibly nil) id that the message refers to.
func (e *eval) Dereference(r *capabilities.ScopeReference) (*session.Scope, error) {
	if r == nil {
		return nil, nil
	}
	ret := &session.Scope{}

	switch t := r.Kind.(type) {
	case nil:
		return nil, nil
	case *capabilities.ScopeReference_SuperToken:
		ret.Kind = &session.Scope_SuperToken{SuperToken: true}

	case *capabilities.ScopeReference_OnPrincipal:
		if idMsg, err := e.Resolve(t.OnPrincipal); err != nil {
			return nil, err
		} else if idMsg == nil {
			ret.Kind = &session.Scope_OnPrincipal{}
		} else if pID, ok := idMsg.(*principal.ID); !ok {
			return nil, errors.Errorf("%s is not a *principal.ID", r)
		} else {
			ret.Kind = &session.Scope_OnPrincipal{OnPrincipal: pID}
		}

	case *capabilities.ScopeReference_OnLocation:
		if idMsg, err := e.Resolve(t.OnLocation.TenantId); err != nil {
			return nil, err
		} else if idMsg == nil {
			ret.Kind = &session.Scope_OnLocation{OnLocation: &session.Location{}}
		} else if tID, _ := idMsg.(*tenant.ID); tID == nil {
			return nil, errors.Errorf("%s is not a *tenant.ID", r)
		} else {
			ret.Kind = &session.Scope_OnLocation{OnLocation: &session.Location{TenantId: tID}}
		}

		if str, err := e.Resolve(t.OnLocation.Path); err != nil {
			return nil, err
		} else if str == nil {
			// No action.
		} else if val, _ := str.(*wrappers.StringValue); val == nil {
			return nil, errors.Errorf("%s is not a string", r)
		} else {
			ret.GetOnLocation().Path = val.Value
		}

	default:
		return nil, errors.Errorf("unimplemented %T", t)
	}

	return ret, nil
}

func (e *eval) Eval(r *capabilities.Rule) (bool, error) {
	e.rules = append(e.rules, r)
	defer func() { e.rules = e.rules[:len(e.rules)-1] }()

	isAllowed := func(goal *session.Session) (bool, error) {
		// Fast-path: The session token already grants the requested goal.
		if goal.IsSubsetOf(e.sn) {
			return true, nil
		}

		// If the session provides delegation access to the principal
		// associated with the request, do a lookup for an active
		// session that satisfies the goal.
		if e.sn.GetScope().GetOnPrincipal() != nil && e.sn.GetCapabilities().GetDelegate() {
			// Swap out the effective requester.
			fake := &session.Session{PrincipalId: e.sn.GetScope().GetOnPrincipal()}
			c := &tokenCollector{ctx: session.WithSession(e, fake)}
			err := e.tokens.Find(goal.Scope, c)
			if err != nil {
				return false, err
			}
			for i := range c.sessions {
				if goal.IsSubsetOf(c.sessions[i]) {
					return true, nil
				}
			}
		}

		return false, nil
	}

	switch t := r.Kind.(type) {
	case *capabilities.Rule_And_:
		for i := range t.And.Rule {
			ok, err := e.Eval(t.And.Rule[i])
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil

	case *capabilities.Rule_AuthStatus_:
		switch t.AuthStatus {
		case capabilities.Rule_LOGGED_IN:
			return e.sn != nil && !proto.Equal(principal.Unauthenticated, e.sn.PrincipalId), nil
		case capabilities.Rule_PUBLIC:
			return true, nil
		case capabilities.Rule_SUPER:
			return e.sn.GetScope().GetSuperToken(), nil
		default:
			panic(fmt.Sprintf("unimplemented: %d", t.AuthStatus))
		}

	case *capabilities.Rule_Direction:
		return e.direction == t.Direction, nil

	case *capabilities.Rule_Eq_:
		a, err := e.Resolve(t.Eq.A)
		if err != nil {
			return false, err
		}
		b, err := e.Resolve(t.Eq.B)
		if err != nil {
			return false, err
		}
		return proto.Equal(a, b), nil

	case *capabilities.Rule_May:
		var err error
		goal := proto.Clone(e.sn).(*session.Session)
		goal.Capabilities = t.May.Capabilities
		goal.Scope, err = e.Dereference(t.May.Scope)
		if err != nil {
			return false, nil
		}
		return isAllowed(goal)

	case *capabilities.Rule_IsSubset:
		if len(e.messages) == 0 {
			return false, nil
		}
		goal, ok := e.messages[len(e.messages)-1].(*session.Session)
		if !ok {
			return false, nil
		}
		return isAllowed(goal)

	case *capabilities.Rule_Never:
		return false, nil

	case *capabilities.Rule_Not:
		ok, err := e.Eval(t.Not)
		return !ok, err

	case *capabilities.Rule_Or_:
		for i := range t.Or.Rule {
			if ok, err := e.Eval(t.Or.Rule[i]); err != nil {
				return false, err
			} else if ok {
				return true, nil
			}
		}
		return false, nil

	default:
		panic(fmt.Sprintf("unimplemented: %T", t))
	}
}

func (e *eval) Filter(msg proto.Message) (bool, error) {
	if e.seen[msg] {
		return true, nil
	}
	e.seen[msg] = true

	e.Push(msg)
	defer e.Pop()

	ref := msg.ProtoReflect()
	if rule := e.ruleMap[ref.Descriptor()]; rule != nil {
		ok, err := e.Eval(rule)
		if err != nil {
			return false, err
		}
		if !ok {
			if x, ok := msg.(interface{ Reset() }); ok {
				e.logger.Tracef("filtering a %T because %s", msg, rule)
				x.Reset()
			}
			return false, nil
		}
	}

	ret := true
	var err error
	ref.Range(func(fd protoreflect.FieldDescriptor, val protoreflect.Value) bool {
		if rule := e.ruleMap[fd]; rule != nil {
			push := false && fd.Kind() == protoreflect.MessageKind
			if push {
				valMsg := val.Message().Interface()
				e.Push(valMsg)
			}
			valOK, valErr := e.Eval(rule)
			if push {
				e.Pop()
			}
			if valErr != nil {
				err = valErr
				return false
			}
			if !valOK {
				e.logger.Tracef("clearing %s because %s", fd.FullName(), rule)
				ref.Clear(fd)
				ret = false
			}
		}

		if ok, walkErr := e.Walk(val); walkErr != nil {
			err = walkErr
			return false
		} else if !ok {
			ret = false
		}

		return true
	})

	return ret, err
}

func (e *eval) Pop() proto.Message {
	ret := e.messages[len(e.messages)-1]
	e.messages = e.messages[:len(e.messages)-1]
	e.ids = e.ids[:len(e.ids)-1]
	return ret
}

// Push adds the given message to the stack.  If an ID can be extracted
// from the message, it will be added to the ID stack. Otherwise, the ID
// stack will be extended.
func (e *eval) Push(msg proto.Message) {
	e.messages = append(e.messages, msg)

	id := e.idMap.extract(msg)
	if id == nil && len(e.ids) > 0 {
		id = e.ids[len(e.ids)-1]
	}
	e.ids = append(e.ids, id)
}

func (e *eval) Walk(val protoreflect.Value) (bool, error) {
	switch t := val.Interface().(type) {
	case protoreflect.Message:
		return e.Filter(t.Interface())

	case protoreflect.List:
		ret := true
		for i, j := 0, t.Len(); i < j; i++ {
			if ok, err := e.Walk(t.Get(i)); err != nil {
				return false, err
			} else if !ok {
				ret = false
			}
		}
		return ret, nil

	case protoreflect.Map:
		ret := true
		var err error
		t.Range(func(_ protoreflect.MapKey, val protoreflect.Value) bool {
			if ok, valErr := e.Walk(val); valErr != nil {
				err = valErr
				return false
			} else if !ok {
				ret = false
			}
			return true
		})
		return ret, err

	default:
		return true, nil
	}
}

type tokenCollector struct {
	grpc.ServerStream
	ctx      context.Context
	sessions []*session.Session
}

func (c *tokenCollector) Context() context.Context {
	return c.ctx
}

func (c *tokenCollector) Send(sn *session.Session) error {
	c.sessions = append(c.sessions, sn)
	return nil
}
