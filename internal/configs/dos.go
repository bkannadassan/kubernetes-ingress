package configs

import "github.com/nginxinc/kubernetes-ingress/internal/configs/version2"

// appProtectDosResource holds the file names of APDosPolicy and APDosLogConf resources used in an Ingress resource.
type appProtectDosResource struct {
	AppProtectDosEnable       string
	AppProtectDosLogEnable    bool
	AppProtectDosMonitor      string
	AppProtectDosName         string
	AppProtectDosAccessLogDst string
	AppProtectDosPolicyFile   string
	AppProtectDosLogConfFile  string
}

func getAppProtectDosResource(dosEx *DosProtectedEx) *appProtectDosResource {
	var dosResource appProtectDosResource
	if dosEx != nil {
		if dosEx.DosProtected != nil {
			protected := dosEx.DosProtected
			dosResource.AppProtectDosEnable = "off"
			if getDosProtectedBoolValue(protected, "spec", "enable") {
				dosResource.AppProtectDosEnable = "on"
			}
			dosResource.AppProtectDosName = getDosProtectedStringValue(protected, "spec", "name")
			dosResource.AppProtectDosMonitor = getDosProtectedStringValue(protected, "spec", "apDosMonitor")
			dosResource.AppProtectDosAccessLogDst = getDosProtectedStringValue(protected, "spec", "dosAccessLogDest")

			if dosEx.DosPolicy != nil {
				pol := dosEx.DosPolicy
				policyFileName := appProtectDosPolicyFileNameFromUnstruct(pol)
				dosResource.AppProtectDosPolicyFile = policyFileName
			}

			if dosEx.DosLogConf != nil {
				log := dosEx.DosLogConf
				logConfFileName := appProtectDosLogConfFileNameFromUnstruct(log)
				logDest := getDosProtectedStringValue(protected, "spec", "dosSecurityLog", "dosLogDest")
				dosResource.AppProtectDosLogConfFile = logConfFileName + " " + generateDosLogDest(logDest)
				dosResource.AppProtectDosLogEnable = getDosProtectedBoolValue(protected, "spec", "dosSecurityLog", "enable")
			}
		}
	}

	return &dosResource
}

func generateDosCfg(dosResource *appProtectDosResource) *version2.Dos {
	if dosResource == nil {
		return nil
	}
	dos := &version2.Dos{}
	dos.Enable = dosResource.AppProtectDosEnable
	dos.Name = dosResource.AppProtectDosName
	dos.ApDosMonitor = dosResource.AppProtectDosMonitor
	dos.ApDosAccessLogDest = dosResource.AppProtectDosAccessLogDst
	dos.ApDosPolicy = dosResource.AppProtectDosPolicyFile
	dos.ApDosSecurityLogEnable = dosResource.AppProtectDosLogEnable
	dos.ApDosLogConf = dosResource.AppProtectDosLogConfFile
	return dos
}
