package validation

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"
)

var appProtectDosPolicyRequiredFields = [][]string{
	{"spec"},
}

var appProtectDosLogConfRequiredFields = [][]string{
	{"spec", "content"},
	{"spec", "filter"},
}

const MaxNameLength = 63

func ValidateDosProtectedResource(protected *unstructured.Unstructured) error {
	name := protected.GetName()

	_, has, err := unstructured.NestedBool(protected.Object, "spec", "enable")
	if err != nil {
		return fmt.Errorf("error validating Dos Protected Resource %v: %w", name, err)
	}
	if !has {
		return fmt.Errorf("DosProtectedResource %v: missing field: spec/%v", name, "enable")
	}

	err = validateProtectedStringField(protected, validateAppProtectDosName, "spec", "name")
	if err != nil {
		return fmt.Errorf("error validating Dos Protected resource %v: %w", name, err)
	}

	err = validateProtectedStringField(protected, validateAppProtectDosMonitor, "spec", "apDosMonitor")
	if err != nil {
		return fmt.Errorf("error validating Dos Protected resource %v: %w", name, err)
	}

	err = validateProtectedStringField(protected, validateAppProtectDosLogDest, "spec", "dosAccessLogDest")
	if err != nil {
		return fmt.Errorf("error validating Dos Protected resource %v: %w", name, err)
	}

	_, hasPolicy, err := unstructured.NestedFieldNoCopy(protected.Object, "spec", "apDosPolicy")
	if err != nil {
		return fmt.Errorf("error validating Dos Protected Resource %v: %w", name, err)
	}
	if hasPolicy {
		err = validateProtectedStringField(protected, validateResourceReference, "spec", "apDosPolicy")
		if err != nil {
			return fmt.Errorf("error validating Dos Protected resource %v: %w", name, err)
		}
	}

	_, hasLogConf, err := unstructured.NestedFieldNoCopy(protected.Object, "spec", "dosSecurityLog")
	if err != nil {
		return fmt.Errorf("error validating Dos Protected Resource %v: %w", name, err)
	}
	if hasLogConf {
		_, has, err = unstructured.NestedBool(protected.Object, "spec", "dosSecurityLog", "enable")
		if err != nil {
			return fmt.Errorf("error validating Dos Protected Resource %v: %w", name, err)
		}
		if !has {
			return fmt.Errorf("DosProtectedResource %v: missing field: spec/%v", name, "dosSecurityLog/enable")
		}

		err = validateProtectedStringField(protected, validateResourceReference, "spec", "dosSecurityLog", "apDosLogConf")
		if err != nil {
			return fmt.Errorf("error validating Dos Protected resource %v: %w", name, err)
		}

		err = validateProtectedStringField(protected, validateAppProtectDosLogDest, "spec", "dosSecurityLog", "dosLogDest")
		if err != nil {
			return fmt.Errorf("error validating Dos Protected resource %v: %w", name, err)
		}
	}

	return nil
}

func validateProtectedStringField(protected *unstructured.Unstructured, validateFunc func(s string) error, path ...string) error {
	value, has, err := unstructured.NestedString(protected.Object, path...)
	if err != nil {
		return fmt.Errorf("error validating field: %w", err)
	}

	if !has {
		return fmt.Errorf("missing field: %v", strings.Join(path, "/"))
	}

	if validateFunc != nil {
		err = validateFunc(value)
		if err != nil {
			return fmt.Errorf("error validating field '%v': %w", strings.Join(path, "/"), err)
		}
	}

	return nil
}

// validateResourceReference validates a resource reference. A valid resource can be either namespace/name or name.
func validateResourceReference(ref string) error {
	errs := validation.IsQualifiedName(ref)
	if len(errs) != 0 {
		return fmt.Errorf("reference name is invalid: %v", ref)
	}

	return nil
}

// ValidateAppProtectDosLogConf validates LogConfiguration resource
func ValidateAppProtectDosLogConf(logConf *unstructured.Unstructured) error {
	lcName := logConf.GetName()
	err := ValidateRequiredFields(logConf, appProtectDosLogConfRequiredFields)
	if err != nil {
		return fmt.Errorf("error validating App Protect Dos Log Configuration %v: %w", lcName, err)
	}

	return nil
}

var (
	validDnsRegex       = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9-]{1,62}\.)([A-Za-z0-9-]{1,63}\.)*[A-Za-z]{2,6}:\d{1,5}$`)
	validIpRegex        = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$`)
	validLocalhostRegex = regexp.MustCompile(`^localhost:\d{1,5}$`)
)

func validateAppProtectDosLogDest(dstAntn string) error {
	if validIpRegex.MatchString(dstAntn) || validDnsRegex.MatchString(dstAntn) || validLocalhostRegex.MatchString(dstAntn) {
		chunks := strings.Split(dstAntn, ":")
		err := validatePort(chunks[1])
		if err != nil {
			return fmt.Errorf("invalid log destination: %w", err)
		}
		return nil
	}
	if dstAntn == "stderr" {
		return nil
	}

	return fmt.Errorf("invalid log destination: %s, must follow format: <ip-address | localhost | dns name>:<port> or stderr", dstAntn)
}

func validatePort(value string) error {
	port, _ := strconv.Atoi(value)
	if port > 65535 || port < 1 {
		return fmt.Errorf("error parsing port: %v not a valid port number", port)
	}
	return nil
}

func validateAppProtectDosName(name string) error {
	if len(name) > MaxNameLength {
		return fmt.Errorf("app Protect Dos Name max length is %v", MaxNameLength)
	}

	if err := validateEscapedString(name, "protected-object-one"); err != nil {
		return err
	}

	return nil
}

func validateAppProtectDosMonitor(monitor string) error {
	_, err := url.Parse(monitor)
	if err != nil {
		return fmt.Errorf("app Protect Dos Monitor must have valid URL")
	}

	if err := validateEscapedString(monitor, "http://www.example.com"); err != nil {
		return err
	}

	return nil
}

// ValidateAppProtectDosPolicy validates Policy resource
func ValidateAppProtectDosPolicy(policy *unstructured.Unstructured) error {
	polName := policy.GetName()

	err := ValidateRequiredFields(policy, appProtectDosPolicyRequiredFields)
	if err != nil {
		return fmt.Errorf("error validating App Protect Dos Policy %v: %w", polName, err)
	}

	return nil
}
