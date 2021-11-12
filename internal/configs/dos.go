package configs

import "github.com/nginxinc/kubernetes-ingress/internal/configs/version2"

// appProtectDosResources holds the file names of APDosPolicy and APDosLogConf resources used in an Ingress resource.
type appProtectDosResources struct {
	AppProtectDosEnable       string
	AppProtectDosLogEnable    bool
	AppProtectDosMonitor      string
	AppProtectDosName         string
	AppProtectDosAccessLogDst string
	AppProtectDosPolicyFile   string
	AppProtectDosLogConfFile  string
}

func getAppProtectDosResources(dosEx *DosProtectedEx) *appProtectDosResources {
	var dosResources appProtectDosResources
	if dosEx != nil {
		if dosEx.DosProtected != nil {
			protected := dosEx.DosProtected
			dosResources.AppProtectDosEnable = "off"
			if getDosProtectedBoolValue(protected, "spec", "enable") {
				dosResources.AppProtectDosEnable = "on"
			}
			dosResources.AppProtectDosName = getDosProtectedStringValue(protected, "spec", "name")
			dosResources.AppProtectDosMonitor = getDosProtectedStringValue(protected, "spec", "apDosMonitor")
			dosResources.AppProtectDosAccessLogDst = getDosProtectedStringValue(protected, "spec", "dosAccessLogDest")

			if dosEx.DosPolicy != nil {
				pol := dosEx.DosPolicy
				policyFileName := appProtectDosPolicyFileNameFromUnstruct(pol)
				dosResources.AppProtectDosPolicyFile = policyFileName
			}

			if dosEx.DosLogConf != nil {
				log := dosEx.DosLogConf
				logConfFileName := appProtectDosLogConfFileNameFromUnstruct(log)
				logDest := getDosProtectedStringValue(protected, "spec", "dosSecurityLog", "dosLogDest")
				dosResources.AppProtectDosLogConfFile = logConfFileName + " " + generateDosLogDest(logDest)
				dosResources.AppProtectDosLogEnable = getDosProtectedBoolValue(protected, "spec", "dosSecurityLog", "enable")
			}
		}
	}

	return &dosResources
}

func generateDosCfg(dosResources *appProtectDosResources) *version2.Dos {
	if dosResources == nil {
		return nil
	}
	dos := &version2.Dos{}
	dos.Enable = dosResources.AppProtectDosEnable
	dos.Name = dosResources.AppProtectDosName
	dos.ApDosMonitor = dosResources.AppProtectDosMonitor
	dos.ApDosAccessLogDest = dosResources.AppProtectDosAccessLogDst
	dos.ApDosPolicy = dosResources.AppProtectDosPolicyFile
	dos.ApDosSecurityLogEnable = dosResources.AppProtectDosLogEnable
	dos.ApDosLogConf = dosResources.AppProtectDosLogConfFile
	return dos
}
