package configs

import (
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestUpdateApDosResources(t *testing.T) {
	appProtectDosPolicy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "test-ns",
				"name":      "test-name",
			},
		},
	}
	appProtectDosLogConf := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "test-ns",
				"name":      "test-name",
			},
			"spec": map[string]interface{}{
				"enable":           true,
				"name":             "dos.example.com",
				"apDosMonitor":     "monitor-name",
				"dosAccessLogDest": "access-log-dest",
			},
		},
	}
	appProtectDosProtected := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "test-ns",
				"name":      "test-name",
			},
			"spec": map[string]interface{}{
				"enable":           true,
				"name":             "dos.example.com",
				"apDosMonitor":     "monitor-name",
				"dosAccessLogDest": "access-log-dest",
			},
		},
	}
	appProtectDosProtectedWithLog := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "test-ns",
				"name":      "test-name",
			},
			"spec": map[string]interface{}{
				"enable":           true,
				"name":             "dos.example.com",
				"apDosMonitor":     "monitor-name",
				"dosAccessLogDest": "access-log-dest",
				"dosSecurityLog": map[string]interface{}{
					"dosLogDest": "log-dest",
					"enable":     true,
				},
			},
		},
	}

	tests := []struct {
		dosProtectedEx *DosProtectedEx
		expected       *appProtectDosResources
		msg            string
	}{
		{
			dosProtectedEx: &DosProtectedEx{},
			expected:       &appProtectDosResources{},
			msg:            "no app protect dos resources",
		},
		{
			dosProtectedEx: &DosProtectedEx{
				DosProtected: appProtectDosProtected,
			},
			expected: &appProtectDosResources{
				AppProtectDosEnable:       "on",
				AppProtectDosName:         "dos.example.com",
				AppProtectDosMonitor:      "monitor-name",
				AppProtectDosAccessLogDst: "access-log-dest",
			},
			msg: "app protect basic protected config",
		},
		{
			dosProtectedEx: &DosProtectedEx{
				DosProtected: appProtectDosProtected,
				DosPolicy:    appProtectDosPolicy,
			},
			expected: &appProtectDosResources{
				AppProtectDosEnable:       "on",
				AppProtectDosName:         "dos.example.com",
				AppProtectDosMonitor:      "monitor-name",
				AppProtectDosAccessLogDst: "access-log-dest",
				AppProtectDosPolicyFile:   "/etc/nginx/dos/policies/test-ns_test-name.json",
			},
			msg: "app protect dos policy",
		},
		{
			dosProtectedEx: &DosProtectedEx{
				DosProtected: appProtectDosProtectedWithLog,
				DosPolicy:    appProtectDosPolicy,
				DosLogConf:   appProtectDosLogConf,
			},
			expected: &appProtectDosResources{
				AppProtectDosEnable:       "on",
				AppProtectDosName:         "dos.example.com",
				AppProtectDosMonitor:      "monitor-name",
				AppProtectDosAccessLogDst: "access-log-dest",
				AppProtectDosPolicyFile:   "/etc/nginx/dos/policies/test-ns_test-name.json",
				AppProtectDosLogEnable:    true,
				AppProtectDosLogConfFile:  "/etc/nginx/dos/logconfs/test-ns_test-name.json syslog:server=log-dest",
			},
			msg: "app protect dos policy and log conf",
		},
	}

	for _, test := range tests {
		result := getAppProtectDosResources(test.dosProtectedEx)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("updateApResources() returned \n%v but expected\n%v for the case of %s", result, test.expected, test.msg)
		}
	}
}
