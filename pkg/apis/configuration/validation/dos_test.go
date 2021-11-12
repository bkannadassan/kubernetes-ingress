package validation

import (
	"fmt"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestValidateAppProtectDosAccessLogDest(t *testing.T) {
	// Positive test cases
	posDstAntns := []string{
		"10.10.1.1:514",
		"localhost:514",
		"dns.test.svc.cluster.local:514",
		"cluster.local:514",
		"dash-test.cluster.local:514",
	}

	// Negative test cases item, expected error message
	negDstAntns := [][]string{
		{"NotValid", "invalid log destination: NotValid, must follow format: <ip-address | localhost | dns name>:<port> or stderr"},
		{"cluster.local", "invalid log destination: cluster.local, must follow format: <ip-address | localhost | dns name>:<port> or stderr"},
		{"-cluster.local:514", "invalid log destination: -cluster.local:514, must follow format: <ip-address | localhost | dns name>:<port> or stderr"},
		{"10.10.1.1:99999", "not a valid port number"},
	}

	for _, tCase := range posDstAntns {
		err := validateAppProtectDosLogDest(tCase)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	}

	for _, nTCase := range negDstAntns {
		err := validateAppProtectDosLogDest(nTCase[0])
		if err == nil {
			t.Errorf("got no error expected error containing '%s'", nTCase[1])
		} else {
			if !strings.Contains(err.Error(), nTCase[1]) {
				t.Errorf("got '%v', expected: '%s'", err, nTCase[1])
			}
		}
	}
}

func TestValidateAppProtectDosLogConf(t *testing.T) {
	tests := []struct {
		logConf   *unstructured.Unstructured
		expectErr bool
		msg       string
	}{
		{
			logConf: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"content": map[string]interface{}{},
						"filter":  map[string]interface{}{},
					},
				},
			},
			expectErr: false,
			msg:       "valid log conf",
		},
		{
			logConf: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"filter": map[string]interface{}{},
					},
				},
			},
			expectErr: true,
			msg:       "invalid log conf with no content field",
		},
		{
			logConf: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"content": map[string]interface{}{},
					},
				},
			},
			expectErr: true,
			msg:       "invalid log conf with no filter field",
		},
		{
			logConf: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"something": map[string]interface{}{
						"content": map[string]interface{}{},
						"filter":  map[string]interface{}{},
					},
				},
			},
			expectErr: true,
			msg:       "invalid log conf with no spec field",
		},
	}

	for _, test := range tests {
		err := ValidateAppProtectDosLogConf(test.logConf)
		if test.expectErr && err == nil {
			t.Errorf("validateAppProtectDosLogConf() returned no error for the case of %s", test.msg)
		}
		if !test.expectErr && err != nil {
			t.Errorf("validateAppProtectDosLogConf() returned unexpected error %v for the case of %s", err, test.msg)
		}
	}
}

func TestValidateAppProtectDosPolicy(t *testing.T) {
	tests := []struct {
		policy    *unstructured.Unstructured
		expectErr bool
		msg       string
	}{
		{
			policy: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{},
				},
			},
			expectErr: false,
			msg:       "valid policy",
		},
		{
			policy: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"something": map[string]interface{}{},
				},
			},
			expectErr: true,
			msg:       "invalid policy with no spec field",
		},
	}

	for _, test := range tests {
		err := ValidateAppProtectDosPolicy(test.policy)
		if test.expectErr && err == nil {
			t.Errorf("validateAppProtectPolicy() returned no error for the case of %s", test.msg)
		}
		if !test.expectErr && err != nil {
			t.Errorf("validateAppProtectPolicy() returned unexpected error %v for the case of %s", err, test.msg)
		}
	}
}

func TestValidateAppProtectDosName(t *testing.T) {
	// Positive test cases
	posDstAntns := []string{"example.com", "\\\"example.com\\\""}

	// Negative test cases item, expected error message
	negDstAntns := [][]string{
		{"very very very very very very very very very very very very very very very very very very long Name", fmt.Sprintf(`App Protect Dos Name max length is %v`, MaxNameLength)},
		{"example.com\\", "must have all '\"' (double quotes) escaped and must not end with an unescaped '\\' (backslash) (e.g. 'protected-object-one', regex used for validation is '([^\"\\\\]|\\\\.)*')"},
		{"\"example.com\"", "must have all '\"' (double quotes) escaped and must not end with an unescaped '\\' (backslash) (e.g. 'protected-object-one', regex used for validation is '([^\"\\\\]|\\\\.)*')"},
	}

	for _, tCase := range posDstAntns {
		err := validateAppProtectDosName(tCase)
		if err != nil {
			t.Errorf("got %v expected nil", err)
		}
	}

	for _, nTCase := range negDstAntns {
		err := validateAppProtectDosName(nTCase[0])
		if err == nil {
			t.Errorf("got no error expected error containing %s", nTCase[1])
		} else {
			if !strings.Contains(err.Error(), nTCase[1]) {
				t.Errorf("got %v expected to contain: %s", err, nTCase[1])
			}
		}
	}
}

func TestValidateAppProtectDosMonitor(t *testing.T) {
	// Positive test cases
	posDstAntns := []string{"example.com", "https://example.com/good_path"}

	// Negative test cases item, expected error message
	negDstAntns := [][]string{
		{"http://example.com/%", "App Protect Dos Monitor must have valid URL"},
		{"http://example.com/\\", "must have all '\"' (double quotes) escaped and must not end with an unescaped '\\' (backslash) (e.g. 'http://www.example.com', regex used for validation is '([^\"\\\\]|\\\\.)*')"},
	}

	for _, tCase := range posDstAntns {
		err := validateAppProtectDosMonitor(tCase)
		if err != nil {
			t.Errorf("got %v expected nil", err)
		}
	}

	for _, nTCase := range negDstAntns {
		err := validateAppProtectDosMonitor(nTCase[0])
		if err == nil {
			t.Errorf("got no error expected error containing %s", nTCase[1])
		} else {
			if !strings.Contains(err.Error(), nTCase[1]) {
				t.Errorf("got %v expected to contain: %s", err, nTCase[1])
			}
		}
	}
}
