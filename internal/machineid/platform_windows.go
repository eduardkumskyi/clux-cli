//go:build windows

package machineid

import "golang.org/x/sys/windows/registry"

// platformID is the MachineGuid written at Windows setup.
func platformID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	return v, err
}
