package ftype

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	DIRMODE         = 0755
	FILEMODE        = 0644
	ft              = "ftype"
	sc              = `SOFTWARE\Classes`
	sra             = `SOFTWARE\RegisteredApplications`
	sa              = `SOFTWARE\Microsoft\Windows\Shell\Associations`
	row             = `SOFTWARE\Microsoft\Windows\Roaming\OpenWith`
	cve             = `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer`
	ua              = "UrlAssociations"
	fa              = `FileAssociations`
	fe              = "FileExts"
	access   uint32 = registry.READ
)

func EnumClassesRoot(do func(assoc, progId, command string), ok func(subKeyName string) bool) {
	assocs, _ := registry.CLASSES_ROOT.ReadSubKeyNames(0)
	for _, assoc := range assocs {
		if ok == nil || ok(assoc) {
			// Дальше файлы как у `assoc` или протоколы URL
			progId, command := Assoc2progIdCommand(assoc)
			do(assoc, progId, command)
		}
	}
}

// Из CLASSES_ROOT.
// Как в cmd /c assoc.
func Assoc2command(assoc string) (progId, command string) {
	progId, _ = GetStringValue(registry.CLASSES_ROOT, assoc, "")
	if progId == "" {
		return
	}

	if k, err := registry.OpenKey(registry.CLASSES_ROOT, progId, access); err == nil {
		k.Close()
		command, _ = ProgId2command(progId)
	}
	return
}

// Если файл существует
func isFileExist(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return false
	}
	return true
}

// Сохраняем двойные кавычки для `ftype`
func GetCommandLine() string {
	return windows.UTF16PtrToString(windows.GetCommandLine())
}

// К GetStringValue добавлено чтение из WOW64_32KEY
func GetStringValue(r registry.Key, path, k string) (v string, err error) {
	var key registry.Key
	for _, a := range []uint32{access, access | registry.WOW64_32KEY} {
		key, err = registry.OpenKey(r, path, a)
		if err == nil {
			defer key.Close()
			break
		}
	}
	if err != nil {
		return
	}
	v, _, err = key.GetStringValue(k)
	return
}

// К ReadValueNames добавлено чтение из WOW64_32KEY
func ReadValueNames(r registry.Key, path string, n int) (names []string, err error) {
	var key registry.Key
	for _, a := range []uint32{access, access | registry.WOW64_32KEY} {
		key, err = registry.OpenKey(r, path, a)
		if err == nil {
			defer key.Close()
			break
		}
	}
	if err != nil {
		return
	}
	return key.ReadValueNames(n)
}

// Из shell\open\command.
func ProgId2command(progId string) (command string, err error) {
	for _, root := range []registry.Key{registry.CURRENT_USER, registry.LOCAL_MACHINE} {
		command, err = GetStringValue(root,
			filepath.Join(sc, progId, "shell", "open", "command"), "")
		if err == nil {
			return
		}
	}
	return
}

// Из RegisteredApplications.
func Assoc2progIds(assoc string) (progIds []string, err error) {
	for _, root := range []registry.Key{registry.CURRENT_USER, registry.LOCAL_MACHINE} {
		var RegisteredApplications []string
		RegisteredApplications, err = ReadValueNames(root,
			sra, 0)
		if err != nil || len(RegisteredApplications) < 1 {
			continue
		}
		Capabilities := ""
		xa := Assoc2xa(assoc, fa)
		if xa == "" {
			return
		}
		for _, RegisteredApplication := range RegisteredApplications {
			// WinSCP
			Capabilities, err = GetStringValue(root,
				sra, RegisteredApplication)
			// Software\Martin Prikryl\WinSCPCapabilities
			if err != nil || Capabilities == "" {
				continue
			}
			progId, err := GetStringValue(root,
				filepath.Join(Capabilities, xa),
				assoc)
			if err != nil || progId == "" {
				continue
			}
			progIds = append(progIds, progId)
		}
	}
	return
}

// Файл, URL или нет.
func Assoc2xa(assoc, fa string) string {
	if strings.HasPrefix(assoc, ".") {
		return fa
	} else if def, _ := GetStringValue(registry.CLASSES_ROOT, assoc, ""); strings.HasPrefix(def, "URL:") {
		return ua
	}
	return ""
}

// Файл или, URL.
func IsAssoc(assoc string) bool {
	return Assoc2xa(assoc, " ") != ""
}

// Из UserChoice.
// Из RegisteredApplications.
// Из CLASSES_ROOT.
func Assoc2progIdCommand(assoc string) (progId, command string) {
	xs := []string{sa, row}
	xa := Assoc2xa(assoc, fe)
	if strings.HasPrefix(assoc, ".") {
		xs = []string{cve, row}
	}
	if xa != "" {
		for _, x := range xs {
			progId, _ = GetStringValue(registry.CURRENT_USER,
				filepath.Join(x, xa, assoc, "UserChoice"),
				"ProgId")
			if progId != "" {
				break
			}
		}
		if progId != "" {
			command, _ = ProgId2command(progId)
			// fmt.Println(bin, err)
		}
		if command != "" {
			return
		}
	}
	progIds, _ := Assoc2progIds(assoc)
	// fmt.Println(progIds, err)
	if len(progIds) < 1 {
		// Может assoc это progId
		progIds = []string{assoc}
	}
	for _, p := range progIds {
		progId = p
		command, _ = ProgId2command(progId)
		if command != "" {
			return
		}
	}
	progId, command = Assoc2command(assoc)
	return
}

func AntiLoop() (cleanUp func()) {
	e, err := os.Executable()
	// path/type.exe
	if err != nil {
		e = "started"
		// type
	} else {
		e = filepath.Base(e)
		// type.exe
		e = strings.Split(e, ".")[0]
		// type
	}
	tmp := os.TempDir()
	antiLoop := filepath.Join(tmp, e)
	if isFileExist(antiLoop) {
		return
	}
	os.MkdirAll(tmp, DIRMODE)
	if os.WriteFile(antiLoop, []byte{}, FILEMODE) == nil {
		return func() { os.Remove(antiLoop) }
	}
	return
}
