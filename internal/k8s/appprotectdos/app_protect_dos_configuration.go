package appprotectdos

import (
	"fmt"
	"strings"

	"github.com/nginxinc/kubernetes-ingress/internal/configs"
	"github.com/nginxinc/kubernetes-ingress/internal/k8s/appprotect_common"
	"github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/validation"
	"github.com/nginxinc/kubernetes-ingress/pkg/apis/dos/v1beta1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// reasons for invalidity
const (
	failedValidationErrorMsg = "Validation Failed"
)

var (
	// DosPolicyGVR is the group version resource of the appprotectdos policy
	DosPolicyGVR = schema.GroupVersionResource{
		Group:    "appprotectdos.f5.com",
		Version:  "v1beta1",
		Resource: "apdospolicies",
	}

	// DosPolicyGVK is the group version kind of the appprotectdos policy
	DosPolicyGVK = schema.GroupVersionKind{
		Group:   "appprotectdos.f5.com",
		Version: "v1beta1",
		Kind:    "APDosPolicy",
	}

	// DosLogConfGVR is the group version resource of the appprotectdos policy
	DosLogConfGVR = schema.GroupVersionResource{
		Group:    "appprotectdos.f5.com",
		Version:  "v1beta1",
		Resource: "apdoslogconfs",
	}
	// DosLogConfGVK is the group version kind of the appprotectdos policy
	DosLogConfGVK = schema.GroupVersionKind{
		Group:   "appprotectdos.f5.com",
		Version: "v1beta1",
		Kind:    "APDosLogConf",
	}

	// DosProtectedResourceGVR is the group version resource of the dos protected resource
	DosProtectedResourceGVR = schema.GroupVersionResource{
		Group:    "appprotectdos.f5.com",
		Version:  "v1beta1",
		Resource: "dosprotectedresource",
	}
	// DosProtectedResourceGVK is the group version kind of the dos protected resource
	DosProtectedResourceGVK = schema.GroupVersionKind{
		Group:   "appprotectdos.f5.com",
		Version: "v1beta1",
		Kind:    "DosProtectedResource",
	}
)

// Operation defines an operation to perform for an App Protect Dos resource.
type Operation int

const (
	// Delete the config of the resource
	Delete Operation = iota
	// AddOrUpdate the config of the resource
	AddOrUpdate
)

// Change represents a change in an App Protect Dos resource
type Change struct {
	// Op is an operation that needs be performed on the resource.
	Op Operation
	// Resource is the target resource.
	Resource interface{}
}

// Problem represents a problem with an App Protect Dos resource
type Problem struct {
	// Object is a configuration object.
	Object runtime.Object
	// Reason tells the reason. It matches the reason in the events of our configuration objects.
	Reason string
	// Message gives the details about the problem. It matches the message in the events of our configuration objects.
	Message string
}

// Configuration holds representations of App Protect Dos cluster resources
type Configuration struct {
	dosPolicies          map[string]*DosPolicyEx
	dosLogConfs          map[string]*DosLogConfEx
	dosProtectedResource map[string]*DosProtectedResourceEx
}

// NewConfiguration creates a new App Protect Dos Configuration
func NewConfiguration() *Configuration {
	return &Configuration{
		dosPolicies:          make(map[string]*DosPolicyEx),
		dosLogConfs:          make(map[string]*DosLogConfEx),
		dosProtectedResource: make(map[string]*DosProtectedResourceEx),
	}
}

// DosProtectedResourceEx represents an DosProtectedResource cluster resource
type DosProtectedResourceEx struct {
	Obj      *v1beta1.DosProtectedResource
	IsValid  bool
	ErrorMsg string
}

// DosPolicyEx represents an DosPolicy cluster resource
type DosPolicyEx struct {
	Obj      *unstructured.Unstructured
	IsValid  bool
	ErrorMsg string
}

// DosLogConfEx represents an DosLogConf cluster resource
type DosLogConfEx struct {
	Obj      *unstructured.Unstructured
	IsValid  bool
	ErrorMsg string
}

// AddOrUpdatePolicy adds or updates an App Protect Dos Policy to App Protect Dos Configuration
func (ci *Configuration) AddOrUpdatePolicy(policyObj *unstructured.Unstructured) ([]Change, []Problem) {
	resNsName := appprotect_common.GetNsName(policyObj)
	policy, err := createAppProtectDosPolicyEx(policyObj)
	ci.dosPolicies[resNsName] = policy
	if err != nil {
		return []Change{{Op: Delete, Resource: policy}},
			[]Problem{{Object: policyObj, Reason: "Rejected", Message: err.Error()}}
	}
	return []Change{{Op: AddOrUpdate, Resource: policy}}, nil
}

// AddOrUpdateLogConf adds or updates App Protect Dos Log Configuration to App Protect Dos Configuration
func (ci *Configuration) AddOrUpdateLogConf(logConfObj *unstructured.Unstructured) ([]Change, []Problem) {
	resNsName := appprotect_common.GetNsName(logConfObj)
	logConf, err := createAppProtectDosLogConfEx(logConfObj)
	ci.dosLogConfs[resNsName] = logConf
	if err != nil {
		return []Change{{Op: Delete, Resource: logConf}},
			[]Problem{{Object: logConfObj, Reason: "Rejected", Message: err.Error()}}
	}
	return []Change{{Op: AddOrUpdate, Resource: logConf}}, nil
}

// AddOrUpdateDosProtectedResource adds or updates App Protect Dos ProtectedResource Configuration
func (ci *Configuration) AddOrUpdateDosProtectedResource(protectedConf *v1beta1.DosProtectedResource) ([]Change, []Problem) {
	resNsName := protectedConf.Namespace + "/" + protectedConf.Name
	protectedResource, err := createDosProtectedResourceEx(protectedConf)
	ci.dosProtectedResource[resNsName] = protectedResource
	if err != nil {
		return []Change{{Op: Delete, Resource: protectedResource}},
			[]Problem{{Object: protectedConf, Reason: "Rejected", Message: err.Error()}}
	}
	return []Change{{Op: AddOrUpdate, Resource: protectedResource}}, nil
}

func (ci *Configuration) getPolicy(key string) (*unstructured.Unstructured, error) {
	name := appprotect_common.GetNamespacedName(key)
	if obj, ok := ci.dosPolicies[name]; ok {
		if obj.IsValid {
			return obj.Obj, nil
		}
		return nil, fmt.Errorf(obj.ErrorMsg)
	}
	return nil, fmt.Errorf("DosPolicy %s not found", name)
}

func (ci *Configuration) GetLogConf(key string) (*unstructured.Unstructured, error) {
	name := appprotect_common.GetNamespacedName(key)
	if obj, ok := ci.dosLogConfs[name]; ok {
		if obj.IsValid {
			return obj.Obj, nil
		}
		return nil, fmt.Errorf(obj.ErrorMsg)
	}
	return nil, fmt.Errorf("DosLogConf %s not found", name)
}

func (ci *Configuration) GetDosProtected(key string) (*v1beta1.DosProtectedResource, error) {
	name := appprotect_common.GetNamespacedName(key)
	if obj, ok := ci.dosProtectedResource[name]; ok {
		if obj.IsValid {
			return obj.Obj, nil
		}
		return nil, fmt.Errorf(obj.ErrorMsg)
	}
	return nil, fmt.Errorf("DosProtectedResource %s not found", name)
}

func (ci *Configuration) GetDosEx(parentNamespace string, name string) (*configs.DosEx, error) {
	var key = getNsName(parentNamespace, name)
	dosEx := &configs.DosEx{}
	protectedEx, ok := ci.dosProtectedResource[key]
	if !ok {
		return nil, fmt.Errorf("DosProtectedResource %s not found", key)
	}
	if !protectedEx.IsValid {
		return nil, fmt.Errorf(protectedEx.ErrorMsg)
	}
	dosEx.DosProtected = protectedEx.Obj
	if protectedEx.Obj.Spec.ApDosPolicy != "" {
		pol, err := ci.getPolicy(protectedEx.Obj.Spec.ApDosPolicy) // todo add dos protected namespace + test cases
		if err != nil {
			return nil, fmt.Errorf("DosProtectedResource references a missing DosPolicy: %w", err)
		}
		dosEx.DosPolicy = pol
	}
	if protectedEx.Obj.Spec.DosSecurityLog != nil && protectedEx.Obj.Spec.DosSecurityLog.ApDosLogConf != "" {
		log, err := ci.GetLogConf(protectedEx.Obj.Spec.DosSecurityLog.ApDosLogConf) // todo add dos protected namespace + test cases
		if err != nil {
			return nil, fmt.Errorf("DosProtectedResource references a missing DosLogConf: %w", err)
		}
		dosEx.DosLogConf = log
	}
	return dosEx, nil
}

func getNsName(defaultNamespace string, name string) string {
	if !strings.Contains(name, "/") {
		return defaultNamespace + "/" + name
	}
	return name
}

func (ci *Configuration) GetDosProtectedThatReferencedDosPolicy(namespace string, name string) []*v1beta1.DosProtectedResource {
	var protectedResources []*v1beta1.DosProtectedResource
	for _, protectedEx := range ci.dosProtectedResource {
		if !protectedEx.IsValid {
			continue
		}
		protected := protectedEx.Obj
		dosPol := protected.Spec.ApDosPolicy
		if dosPol == (namespace+"/"+name) || (dosPol == name && namespace == protected.Namespace) {
			protectedResources = append(protectedResources, protected)
		}
	}
	return protectedResources
}

func (ci *Configuration) GetDosProtectedThatReferencedDosLogConf(namespace string, name string) []*v1beta1.DosProtectedResource {
	var protectedResources []*v1beta1.DosProtectedResource
	for _, protectedEx := range ci.dosProtectedResource {
		if !protectedEx.IsValid {
			continue
		}
		protected := protectedEx.Obj
		if protected.Spec.DosSecurityLog != nil {
			dosLogConf := protected.Spec.DosSecurityLog.ApDosLogConf
			if dosLogConf == (namespace+"/"+name) || (dosLogConf == name && namespace == protected.Namespace) {
				protectedResources = append(protectedResources, protected)
			}
		}
	}
	return protectedResources
}

// DeletePolicy deletes an App Protect Policy from App Protect Dos Configuration
func (ci *Configuration) DeletePolicy(key string) (changes []Change, problems []Problem) {
	if _, has := ci.dosPolicies[key]; has {
		change := Change{Op: Delete, Resource: ci.dosPolicies[key]}
		delete(ci.dosPolicies, key)
		return append(changes, change), problems
	}
	return changes, problems
}

// DeleteLogConf deletes an App Protect Dos LogConf from App Protect Dos Configuration
func (ci *Configuration) DeleteLogConf(key string) (changes []Change, problems []Problem) {
	if _, has := ci.dosLogConfs[key]; has {
		change := Change{Op: Delete, Resource: ci.dosLogConfs[key]}
		delete(ci.dosLogConfs, key)
		return append(changes, change), problems
	}
	return changes, problems
}

// DeleteProtectedResource deletes an App Protect Dos ProtectedResource Configuration
func (ci *Configuration) DeleteProtectedResource(key string) (changes []Change, problems []Problem) {
	if _, has := ci.dosProtectedResource[key]; has {
		change := Change{Op: Delete, Resource: ci.dosProtectedResource[key]}
		delete(ci.dosProtectedResource, key)
		return append(changes, change), problems
	}
	return changes, problems
}

func createAppProtectDosPolicyEx(policyObj *unstructured.Unstructured) (*DosPolicyEx, error) {
	err := validation.ValidateAppProtectDosPolicy(policyObj)
	if err != nil {
		return &DosPolicyEx{
			Obj:      policyObj,
			IsValid:  false,
			ErrorMsg: failedValidationErrorMsg,
		}, err
	}

	return &DosPolicyEx{
		Obj:     policyObj,
		IsValid: true,
	}, nil
}

func createAppProtectDosLogConfEx(dosLogConfObj *unstructured.Unstructured) (*DosLogConfEx, error) {
	err := validation.ValidateAppProtectDosLogConf(dosLogConfObj)
	if err != nil {
		return &DosLogConfEx{
			Obj:      dosLogConfObj,
			IsValid:  false,
			ErrorMsg: failedValidationErrorMsg,
		}, err
	}
	return &DosLogConfEx{
		Obj:     dosLogConfObj,
		IsValid: true,
	}, nil
}

func createDosProtectedResourceEx(protectedConf *v1beta1.DosProtectedResource) (*DosProtectedResourceEx, error) {
	err := validation.ValidateDosProtectedResource(protectedConf)
	if err != nil {
		return &DosProtectedResourceEx{
			Obj:      protectedConf,
			IsValid:  false,
			ErrorMsg: failedValidationErrorMsg,
		}, err
	}
	return &DosProtectedResourceEx{
		Obj:     protectedConf,
		IsValid: true,
	}, nil
}
