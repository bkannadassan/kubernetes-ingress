package configs

import (
	"reflect"
	"testing"

	"github.com/nginxinc/kubernetes-ingress/pkg/apis/dos/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestUpdateApDosResource(t *testing.T) {
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
				"name":             "dos-protected",
				"apDosMonitor":     "example.com",
				"dosAccessLogDest": "127.0.0.1:5561",
			},
		},
	}
	appProtectDosProtected := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosOnly",
			Namespace: "default",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable:           true,
			Name:             "dos-protected",
			ApDosMonitor:     "example.com",
			DosAccessLogDest: "127.0.0.1:5561",
		},
	}
	appProtectDosProtectedWithLog := &v1beta1.DosProtectedResource{
		TypeMeta: v1.TypeMeta{},
		ObjectMeta: v1.ObjectMeta{
			Name:      "dosWithLogConf",
			Namespace: "default",
		},
		Spec: v1beta1.DosProtectedResourceSpec{
			Enable:           true,
			Name:             "dos-protected",
			ApDosMonitor:     "example.com",
			DosAccessLogDest: "127.0.0.1:5561",
			DosSecurityLog: &v1beta1.DosSecurityLog{
				Enable:       true,
				ApDosLogConf: "dosLogConf",
				DosLogDest:   "syslog-svc.default.svc.cluster.local:514",
			},
		},
	}

	tests := []struct {
		dosProtectedEx *DosEx
		expected       *appProtectDosResource
		msg            string
	}{
		{
			dosProtectedEx: &DosEx{},
			expected:       &appProtectDosResource{},
			msg:            "no app protect dos resources",
		},
		{
			dosProtectedEx: &DosEx{
				DosProtected: appProtectDosProtected,
			},
			expected: &appProtectDosResource{
				AppProtectDosEnable:       "on",
				AppProtectDosName:         "dos-protected",
				AppProtectDosMonitor:      "example.com",
				AppProtectDosAccessLogDst: "127.0.0.1:5561",
			},
			msg: "app protect basic protected config",
		},
		{
			dosProtectedEx: &DosEx{
				DosProtected: appProtectDosProtected,
				DosPolicy:    appProtectDosPolicy,
			},
			expected: &appProtectDosResource{
				AppProtectDosEnable:       "on",
				AppProtectDosName:         "dos-protected",
				AppProtectDosMonitor:      "example.com",
				AppProtectDosAccessLogDst: "127.0.0.1:5561",
				AppProtectDosPolicyFile:   "/etc/nginx/dos/policies/test-ns_test-name.json",
			},
			msg: "app protect dos policy",
		},
		{
			dosProtectedEx: &DosEx{
				DosProtected: appProtectDosProtectedWithLog,
				DosPolicy:    appProtectDosPolicy,
				DosLogConf:   appProtectDosLogConf,
			},
			expected: &appProtectDosResource{
				AppProtectDosEnable:       "on",
				AppProtectDosName:         "dos-protected",
				AppProtectDosMonitor:      "example.com",
				AppProtectDosAccessLogDst: "127.0.0.1:5561",
				AppProtectDosPolicyFile:   "/etc/nginx/dos/policies/test-ns_test-name.json",
				AppProtectDosLogEnable:    true,
				AppProtectDosLogConfFile:  "/etc/nginx/dos/logconfs/test-ns_test-name.json syslog:server=syslog-svc.default.svc.cluster.local:514",
			},
			msg: "app protect dos policy and log conf",
		},
	}

	for _, test := range tests {
		result := getAppProtectDosResource(test.dosProtectedEx)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("updateApResources() returned \n%v but expected\n%v for the case of %s", result, test.expected, test.msg)
		}
	}
}
